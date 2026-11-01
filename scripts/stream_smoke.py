#!/usr/bin/env python3
"""Linux release: 16 actual relays, independent HTTP progress, reload and shutdown."""
from pathlib import Path
import json
import queue
import signal
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'server/target/release/pathward-server'
WS = b'GET /chat HTTP/1.1\r\nHost: app.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n'
SWITCH = b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n'

def head(stream):
    data = b''
    while not data.endswith(b'\r\n\r\n'):
        byte = stream.recv(1)
        assert byte, 'early EOF'
        data += byte
        assert len(data) <= 32768
    return data

def exact(stream, size):
    data = b''
    while len(data) < size:
        part = stream.recv(size - len(data))
        assert part, 'early frame EOF'
        data += part
    return data

def receive(stream):
    data = b''
    while True:
        try:
            part = stream.recv(4096)
        except ConnectionResetError:
            break
        if not part:
            break
        data += part
        assert len(data) < 65536
    return data

with tempfile.TemporaryDirectory(prefix='pathward-streams-') as temporary, socket.socket() as upstream:
    root = Path(temporary)
    upstream.bind(('127.0.0.1', 0))
    upstream.listen(20)
    upstream.settimeout(5)
    backend_port = upstream.getsockname()[1]
    config = root / 'config.kdl'
    def replace(cap):
        pending = root / 'pending.kdl'
        pending.write_text(f'site "app.example" {{\ntls "auto"\nreverse-proxy "127.0.0.1:{backend_port}"\nproxy-stream "websocket"\nproxy-limit "streams" "{cap}"\nproxy-limit "connections" "1"\n}}\n')
        pending.replace(config)
    replace(16)
    process = subprocess.Popen([str(BINARY), 'serve-http', str(config), '127.0.0.1:0', '--monitor', '127.0.0.1:0'], stderr=subprocess.PIPE)
    events = queue.Queue()
    def logs():
        for line in process.stderr:
            events.put(json.loads(line))
    threading.Thread(target=logs, daemon=True).start()
    def event(name):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            item = events.get(timeout=max(.01, deadline - time.monotonic()))
            if item['event'] == name:
                return item
        raise AssertionError(f'missing event: {name}')
    clients, backends = [], []
    try:
        startup = event('listening')
        port, monitor = startup['port'], startup['monitor_port']
        def connect(peer, request=WS):
            s = socket.create_connection(('127.0.0.1', port), timeout=3, source_address=(peer, 0))
            s.sendall(request)
            return s
        for i in range(16):
            client = connect(f'127.0.0.{2 + i // 8}')
            clients.append(client)
            backend, _ = upstream.accept()
            backend.settimeout(3)
            backends.append(backend)
            assert head(backend).startswith(b'GET /chat ')
            backend.sendall(SWITCH)
            assert head(client).startswith(b'HTTP/1.1 101 ')
        with connect('127.0.0.4') as excess:
            assert receive(excess).startswith(b'HTTP/1.1 503 ')
        # All 16 workers actually carry data, not just accepted sockets.
        for client, backend in zip(clients, backends):
            client.sendall(b'\x89\x80\0\0\0\0')
            assert exact(backend, 6) == b'\x89\x80\0\0\0\0'
            backend.sendall(b'\x8a\0')
            assert exact(client, 2) == b'\x8a\0'
        # Ordinary requests use their separate service/admission/worker capacity.
        request = b'GET / HTTP/1.1\r\nHost: app.example\r\n\r\n'
        with connect('127.0.0.4', request) as ordinary:
            backend, _ = upstream.accept()
            with backend:
                backend.settimeout(3)
                head(backend)
                backend.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
            assert receive(ordinary).endswith(b'OK')
        replace(1)
        process.send_signal(signal.SIGHUP)
        event('reload_committed')
        with connect('127.0.0.4') as excess:
            assert receive(excess).startswith(b'HTTP/1.1 503 ')
        for backend, client in zip(backends, clients):
            backend.sendall(b'\x8a\0')
            assert exact(client, 2) == b'\x8a\0'
        # Gauge counts each established connection once across handoff.
        with socket.create_connection(('127.0.0.1', monitor), timeout=3) as probe:
            probe.sendall(b'GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n')
            assert b'pathward_connections_active 16\n' in receive(probe)
        process.send_signal(signal.SIGTERM)
        for client in clients:
            assert receive(client) == b''
        assert process.wait(timeout=8) == 0
    finally:
        for stream in clients + backends:
            stream.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
print('Stream test passed: 16 relays, global rejection, independent HTTP, reduced live cap, pinned sessions, gauge and shutdown.')
