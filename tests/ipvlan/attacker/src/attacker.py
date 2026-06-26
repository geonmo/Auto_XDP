#!/usr/bin/env python3
"""Attacker on VM.5 — sends unsolicited TCP connections to the IPVLAN container.

Scenario 2: VM.5 ──SYN──▶ container:8080
  Expected result: timeout (XDP_DROP)
  Bad result:      connected / refused (XDP_PASS)
"""

import os
import socket
import threading
import time
from collections import deque
from flask import Flask, jsonify, request
from flask_cors import CORS

API_PORT  = int(os.environ.get('API_PORT', 8001))
NODE_NAME = os.environ.get('NODE_NAME', 'attacker-vm5')

app = Flask(__name__)
CORS(app)

lock         = threading.Lock()
result_log   = deque(maxlen=500)
_attack_thr  = None

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

@app.route('/api/reset', methods=['POST'])
def reset():
    with lock:
        state.update({
            'running': False, 'target': '', 'port': 8080, 'count': 0,
            'sent': 0, 'timeout': 0, 'refused': 0, 'connected': 0, 'error': 0,
        })
        result_log.clear()
    return jsonify({'status': 'reset'})

if __name__ == '__main__':
    print(f'[attacker] REST API :{API_PORT}  node={NODE_NAME}')
    app.run(host='0.0.0.0', port=API_PORT)
