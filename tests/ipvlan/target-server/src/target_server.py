#!/usr/bin/env python3
"""Target server on VM.4 — receives HTTP requests from the IPVLAN container."""

import os
import threading
import time
from collections import deque
from flask import Flask, jsonify, request
from flask_cors import CORS

LISTEN_PORT = int(os.environ.get('LISTEN_PORT', 8080))
API_PORT    = int(os.environ.get('API_PORT', 9090))
NODE_NAME   = os.environ.get('NODE_NAME', 'target-vm4')

lock  = threading.Lock()
stats = {'total': 0, 'from_container': 0, 'other': 0}
conn_log = deque(maxlen=500)

# ── HTTP target (port LISTEN_PORT) ─────────────────────────────────────────
target_app = Flask('target')
CORS(target_app)

@target_app.route('/', methods=['GET', 'POST'])
@target_app.route('/test', methods=['GET', 'POST'])
def handle_request():
    src = request.remote_addr
    ts  = time.time()
    with lock:
        stats['total'] += 1
        if src.startswith('192.168.100.'):
            stats['from_container'] += 1
        else:
            stats['other'] += 1
        conn_log.append({
            'id':     stats['total'],
            'ts':     ts,
            'ts_str': time.strftime('%H:%M:%S', time.localtime(ts)),
            'src':    src,
            'method': request.method,
            'path':   request.path,
        })
    return jsonify({'status': 'ok', 'server': NODE_NAME, 'ts': ts})

# ── REST stats API (port API_PORT) ─────────────────────────────────────────
api_app = Flask('api')
CORS(api_app)

@api_app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'node': NODE_NAME})

@api_app.route('/api/stats')
def get_stats():
    with lock:
        return jsonify({**stats, 'node': NODE_NAME, 'listen_port': LISTEN_PORT})

@api_app.route('/api/connections')
def get_connections():
    limit = int(request.args.get('limit', 50))
    with lock:
        return jsonify(list(conn_log)[-limit:])

@api_app.route('/api/reset', methods=['POST'])
def reset():
    with lock:
        stats.update({'total': 0, 'from_container': 0, 'other': 0})
        conn_log.clear()
    return jsonify({'status': 'reset'})

if __name__ == '__main__':
    t = threading.Thread(
        target=lambda: target_app.run(host='0.0.0.0', port=LISTEN_PORT, use_reloader=False),
        daemon=True,
    )
    t.start()
    print(f'[target-server] HTTP :{LISTEN_PORT}  REST API :{API_PORT}  node={NODE_NAME}')
    api_app.run(host='0.0.0.0', port=API_PORT)
