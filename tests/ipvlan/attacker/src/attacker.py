#!/usr/bin/env python3
"""Attacker on VM.5 — sends unsolicited TCP connections to the IPVLAN container.

Scenario 2: VM.5 ──SYN──▶ container:8080
  Expected result: timeout (XDP_DROP)
  Bad result:      connected / refused (XDP_PASS)

Scenario 2-c (IP spoof): VM.5 crafts TCP SYN with saddr=<spoof_src> using a raw
  IP socket (requires root / CAP_NET_RAW). The 5-tuple does NOT match any CT entry,
  so XDP must drop even though the source IP looks like a trusted host.
  Expected result: no SYN_RECV on the container (XDP_DROP)
  Bad result:      SYN_RECV seen on the container  (XDP_PASS — spoofed packet leaked)
"""

import os
import random
import socket
import struct
import threading
import time
from collections import deque
from flask import Flask, jsonify, request
from flask_cors import CORS


# ── Raw-packet helpers for IP-spoof tests ─────────────────────────────────────

def _inet_cksum(data: bytes) -> int:
    """Standard one's-complement 16-bit checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack_from('!' + 'H' * (len(data) // 2), data))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def _build_spoofed_syn(spoof_src: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Return a raw IPv4 TCP SYN packet with the given spoofed source address."""
    src_b = socket.inet_aton(spoof_src)
    dst_b = socket.inet_aton(dst_ip)
    seq = random.randint(0, 0xffffffff)

    # TCP header (20 bytes, no options), checksum = 0 first pass
    tcp_doff_flags = (5 << 4)          # data offset = 5 (20 bytes)
    tcp_flags      = 0x02              # SYN
    tcp_hdr = struct.pack('!HHIIBBHHH',
        src_port, dst_port, seq, 0,
        tcp_doff_flags, tcp_flags, 65535, 0, 0)

    # TCP checksum over pseudo-header
    pseudo = struct.pack('!4s4sBBH', src_b, dst_b, 0, socket.IPPROTO_TCP, len(tcp_hdr))
    tcp_ck = _inet_cksum(pseudo + tcp_hdr)
    tcp_hdr = struct.pack('!HHIIBBHHH',
        src_port, dst_port, seq, 0,
        tcp_doff_flags, tcp_flags, 65535, tcp_ck, 0)

    # IP header (20 bytes), checksum = 0 first pass
    ip_tot = 20 + len(tcp_hdr)
    ip_id  = random.randint(0, 0xffff)
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_tot, ip_id, 0,
        64, socket.IPPROTO_TCP, 0, src_b, dst_b)
    ip_ck = _inet_cksum(ip_hdr)
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_tot, ip_id, 0,
        64, socket.IPPROTO_TCP, ip_ck, src_b, dst_b)

    return ip_hdr + tcp_hdr

API_PORT  = int(os.environ.get('API_PORT', 8001))
NODE_NAME = os.environ.get('NODE_NAME', 'attacker-vm5')

app = Flask(__name__)
CORS(app)

lock         = threading.Lock()
result_log   = deque(maxlen=500)
_attack_thr  = None
_spoof_thr   = None

state = {
    'running':   False,
    'target':    '',
    'port':      8080,
    'count':     0,
    'sent':      0,
    'timeout':   0,   # XDP_DROP indicator
    'refused':   0,   # XDP_PASS but no listener
    'connected': 0,   # XDP_PASS + listener (bad!)
    'error':     0,
}

spoof_state = {
    'running':    False,
    'spoof_src':  '',
    'target':     '',
    'port':       0,
    'count':      0,
    'sent':       0,
    'error':      '',   # non-empty if raw socket failed (e.g. not root)
}

def _probe(target, port, timeout_sec):
    """Return (result, elapsed_ms) for one TCP connect attempt."""
    ts = time.monotonic()
    s  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_sec)
    try:
        s.connect((target, port))
        return 'connected', (time.monotonic() - ts) * 1000
    except socket.timeout:
        return 'timeout', (time.monotonic() - ts) * 1000
    except ConnectionRefusedError:
        return 'refused', (time.monotonic() - ts) * 1000
    except OSError as e:
        return f'error:{e}', (time.monotonic() - ts) * 1000
    finally:
        try:
            s.close()
        except Exception:
            pass

def _spoof_worker(spoof_src: str, target: str, port: int, count: int, interval: float):
    """Send raw IP TCP SYN packets with a spoofed source address (requires root)."""
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError as exc:
        with lock:
            spoof_state['running'] = False
            spoof_state['error'] = f'raw socket requires root: {exc}'
        return

    try:
        for _ in range(count):
            with lock:
                if not spoof_state['running']:
                    break
            src_port = random.randint(10000, 60000)
            pkt = _build_spoofed_syn(spoof_src, target, src_port, port)
            try:
                raw_sock.sendto(pkt, (target, 0))
                with lock:
                    spoof_state['sent'] += 1
            except OSError as exc:
                with lock:
                    spoof_state['error'] = str(exc)
                break
            time.sleep(interval)
    finally:
        raw_sock.close()
        with lock:
            spoof_state['running'] = False


def _attack_worker(target, port, count, timeout_sec):
    for i in range(count):
        with lock:
            if not state['running']:
                break
        result, ms = _probe(target, port, timeout_sec)
        with lock:
            state['sent'] += 1
            if result == 'timeout':
                state['timeout'] += 1
            elif result == 'refused':
                state['refused'] += 1
            elif result == 'connected':
                state['connected'] += 1
            else:
                state['error'] += 1
            result_log.append({
                'id':     state['sent'],
                'ts':     time.time(),
                'ts_str': time.strftime('%H:%M:%S'),
                'result': result,
                'ms':     round(ms, 1),
            })
        time.sleep(0.2)
    with lock:
        state['running'] = False

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'node': NODE_NAME})

@app.route('/api/attack', methods=['POST'])
def start_attack():
    global _attack_thr
    data = request.get_json() or {}
    target      = data.get('target', '')
    port        = int(data.get('port', 8080))
    count       = int(data.get('count', 10))
    timeout_sec = float(data.get('timeout', 2.0))

    if not target:
        return jsonify({'error': 'target required'}), 400

    with lock:
        if state['running']:
            return jsonify({'error': 'already running'}), 409
        state.update({
            'running':   True,
            'target':    target,
            'port':      port,
            'count':     count,
            'sent':      0,
            'timeout':   0,
            'refused':   0,
            'connected': 0,
            'error':     0,
        })
        result_log.clear()

    _attack_thr = threading.Thread(
        target=_attack_worker,
        args=(target, port, count, timeout_sec),
        daemon=True,
    )
    _attack_thr.start()
    return jsonify({'status': 'started', 'target': target, 'count': count})

@app.route('/api/attack', methods=['DELETE'])
def stop_attack():
    with lock:
        state['running'] = False
    return jsonify({'status': 'stopped'})

@app.route('/api/attack/status')
def attack_status():
    with lock:
        s = dict(state)
    # Verdict
    if s['sent'] > 0 and not s['running']:
        if s['connected'] == 0 and s['refused'] == 0:
            s['verdict'] = 'XDP_DROP confirmed — all probes timed out'
        elif s['connected'] > 0:
            s['verdict'] = f'XDP_PASS detected — {s["connected"]} connection(s) established!'
        else:
            s['verdict'] = f'XDP_PASS detected — {s["refused"]} RST(s) received'
    else:
        s['verdict'] = 'in progress' if s['running'] else 'not started'
    return jsonify(s)

@app.route('/api/results')
def get_results():
    limit = int(request.args.get('limit', 50))
    with lock:
        return jsonify(list(result_log)[-limit:])

@app.route('/api/spoof', methods=['POST'])
def start_spoof():
    global _spoof_thr
    data = request.get_json() or {}
    spoof_src = data.get('spoof_src', '')
    target    = data.get('target', '')
    port      = int(data.get('port', 8080))
    count     = int(data.get('count', 5))
    interval  = float(data.get('interval', 0.2))

    if not spoof_src or not target:
        return jsonify({'error': 'spoof_src and target required'}), 400

    with lock:
        if spoof_state['running']:
            return jsonify({'error': 'spoof already running'}), 409
        spoof_state.update({
            'running': True, 'spoof_src': spoof_src, 'target': target,
            'port': port, 'count': count, 'sent': 0, 'error': '',
        })

    _spoof_thr = threading.Thread(
        target=_spoof_worker,
        args=(spoof_src, target, port, count, interval),
        daemon=True,
    )
    _spoof_thr.start()
    return jsonify({'status': 'started', 'spoof_src': spoof_src, 'target': target, 'count': count})


@app.route('/api/spoof/status')
def spoof_status():
    with lock:
        return jsonify(dict(spoof_state))


@app.route('/api/reset', methods=['POST'])
def reset():
    with lock:
        state.update({
            'running': False, 'target': '', 'port': 8080, 'count': 0,
            'sent': 0, 'timeout': 0, 'refused': 0, 'connected': 0, 'error': 0,
        })
        result_log.clear()
        spoof_state.update({
            'running': False, 'spoof_src': '', 'target': '', 'port': 0,
            'count': 0, 'sent': 0, 'error': '',
        })
    return jsonify({'status': 'reset'})

if __name__ == '__main__':
    print(f'[attacker] REST API :{API_PORT}  node={NODE_NAME}')
    app.run(host='0.0.0.0', port=API_PORT)
