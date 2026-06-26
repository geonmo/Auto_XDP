#!/usr/bin/env python3
"""Container application (runs inside the IPVLAN container on host).

Role A — HTTP server on LISTEN_PORT (8080):
  Receives inbound connections. If XDP works, unsolicited packets from VM.5
  never arrive here. Tracks `from_attacker` to confirm zero inbound from VM.5.

Role B — HTTP client to TARGET_IP:TARGET_PORT:
  Makes periodic outbound requests every CLIENT_INTERVAL seconds.
  TC egress records each request's reverse tuple in conntrack_map.
  XDP then lets VM.4's replies through.
  Tracks the ephemeral local port used for each connection so scenario 2-b
  can query them via /api/client-ports.

Role C — REST API on API_PORT (7070):
  Exposes stats for test orchestration from run_tests.sh.
"""

import http.client
import os
import threading
import time
import urllib.request
import urllib.error
from collections import deque
from flask import Flask, jsonify, request
from flask_cors import CORS

LISTEN_PORT     = int(os.environ.get('LISTEN_PORT', 8080))
API_PORT        = int(os.environ.get('API_PORT', 7070))
TARGET_IP       = os.environ.get('TARGET_IP', '192.168.100.4')
TARGET_PORT     = int(os.environ.get('TARGET_PORT', 8080))
ATTACKER_IP     = os.environ.get('ATTACKER_IP', '192.168.100.5')
CLIENT_INTERVAL = float(os.environ.get('CLIENT_INTERVAL', '3.0'))
NODE_NAME       = os.environ.get('NODE_NAME', 'container-app')

lock = threading.Lock()

# ── Role A: inbound server stats ───────────────────────────────────────────
server_stats = {'total': 0, 'from_attacker': 0, 'other': 0}
server_log   = deque(maxlen=500)

# ── Role B: outbound client stats ──────────────────────────────────────────
client_stats   = {'total': 0, 'success': 0, 'timeout': 0, 'error': 0}
client_log     = deque(maxlen=500)
client_ports   = deque(maxlen=50)   # last N ephemeral local ports used
_client_active = True


# ── Custom HTTP connection that records the local ephemeral port ────────────
class _PortTrackingHTTPConn(http.client.HTTPConnection):
    """Records the local ephemeral port after connect() so tests can query it."""
    def connect(self):
        super().connect()
        try:
            port = self.sock.getsockname()[1]
            with lock:
                if port not in client_ports:
                    client_ports.appendleft(port)
        except Exception:
            pass


class _PortTrackingHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_PortTrackingHTTPConn, req)


_port_opener = urllib.request.build_opener(_PortTrackingHandler())


# ── Role A: HTTP server ────────────────────────────────────────────────────
server_app = Flask('server')
CORS(server_app)

@server_app.route('/', methods=['GET', 'POST'])
@server_app.route('/echo', methods=['GET', 'POST'])
def echo():
    src = request.remote_addr
    ts  = time.time()
    with lock:
        server_stats['total'] += 1
        if src == ATTACKER_IP:
            server_stats['from_attacker'] += 1
        else:
            server_stats['other'] += 1
        server_log.append({
            'id':     server_stats['total'],
            'ts':     ts,
            'ts_str': time.strftime('%H:%M:%S', time.localtime(ts)),
            'src':    src,
        })
    return jsonify({'echo': True, 'src': src, 'ts': ts, 'node': NODE_NAME})

# ── Role B: client loop ────────────────────────────────────────────────────
def _client_loop():
    req_id = 0
    while True:
        if not _client_active:
            time.sleep(1.0)
            continue
        req_id += 1
        ts  = time.time()
        url = f'http://{TARGET_IP}:{TARGET_PORT}/test'
        try:
            with _port_opener.open(url, timeout=3.0) as resp:
                _ = resp.read()
                result = 'success'
        except urllib.error.URLError as exc:
            reason = str(exc.reason)
            result = 'timeout' if 'timed out' in reason.lower() else f'error:{reason}'
        except Exception as exc:
            result = f'error:{exc}'
        elapsed = (time.time() - ts) * 1000

        with lock:
            client_stats['total'] += 1
            if result == 'success':
                client_stats['success'] += 1
            elif result == 'timeout':
                client_stats['timeout'] += 1
            else:
                client_stats['error'] += 1
            client_log.append({
                'id':     req_id,
                'ts':     ts,
                'ts_str': time.strftime('%H:%M:%S', time.localtime(ts)),
                'result': result,
                'ms':     round(elapsed, 1),
                'target': TARGET_IP,
            })
        time.sleep(CLIENT_INTERVAL)

# ── Role C: REST API ────────────────────────────────────────────────────────
api_app = Flask('api')
CORS(api_app)

@api_app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'node': NODE_NAME})

@api_app.route('/api/server-stats')
def get_server_stats():
    with lock:
        return jsonify({**server_stats, 'node': NODE_NAME, 'attacker_ip': ATTACKER_IP})

@api_app.route('/api/summary')
@api_app.route('/api/client-stats')
def get_client_stats():
    with lock:
        return jsonify({**client_stats, 'node': NODE_NAME, 'target': TARGET_IP})

@api_app.route('/api/client-ports')
def get_client_ports():
    """Return the last N ephemeral local ports used for connections to TARGET_IP:TARGET_PORT."""
    with lock:
        return jsonify({
            'ports': list(client_ports),
            'target': TARGET_IP,
            'target_port': TARGET_PORT,
            'node': NODE_NAME,
        })

@api_app.route('/api/server-log')
def get_server_log():
    limit = int(request.args.get('limit', 50))
    with lock:
        return jsonify(list(server_log)[-limit:])

@api_app.route('/api/client-log')
def get_client_log():
    limit = int(request.args.get('limit', 50))
    with lock:
        return jsonify(list(client_log)[-limit:])

@api_app.route('/api/reset', methods=['POST'])
def reset():
    with lock:
        server_stats.update({'total': 0, 'from_attacker': 0, 'other': 0})
        server_log.clear()
        client_stats.update({'total': 0, 'success': 0, 'timeout': 0, 'error': 0})
        client_log.clear()
        # NOTE: client_ports is NOT cleared on reset so scenario 2-b can query
        # ports that were used before the stats reset.
    return jsonify({'status': 'reset'})

@api_app.route('/api/start-client', methods=['POST'])
def start_client():
    global _client_active
    _client_active = True
    return jsonify({'status': 'client started'})

@api_app.route('/api/stop-client', methods=['POST'])
def stop_client():
    global _client_active
    _client_active = False
    return jsonify({'status': 'client stopped'})

if __name__ == '__main__':
    # Start Role A: HTTP inbound server
    threading.Thread(
        target=lambda: server_app.run(host='0.0.0.0', port=LISTEN_PORT, use_reloader=False),
        daemon=True,
    ).start()

    # Start Role B: outbound client
    threading.Thread(target=_client_loop, daemon=True).start()

    print(f'[container-app] server :{LISTEN_PORT}  api :{API_PORT}  client→{TARGET_IP}:{TARGET_PORT}')
    api_app.run(host='0.0.0.0', port=API_PORT)
