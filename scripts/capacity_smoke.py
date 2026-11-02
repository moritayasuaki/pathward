#!/usr/bin/env python3
"""Shared-NAT opt-in: finite burst, hostile-peer bound and other-peer progress."""
import concurrent.futures
import json
from pathlib import Path
import queue
import signal
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'server/target/release/pathward-server'

def receive(stream):
    data = b''
    while chunk := stream.recv(4096):
        data += chunk
        assert len(data) <= 16384
    return data

def get(port, peer='127.0.0.20', target='/'):
    with socket.create_connection(('127.0.0.1', port), timeout=3, source_address=(peer, 0)) as stream:
        stream.sendall(f'GET {target} HTTP/1.1\r\nHost: example.com\r\n\r\n'.encode())
        return receive(stream)

with tempfile.TemporaryDirectory(prefix='pathward-capacity-') as tmp:
    root = Path(tmp)
    (root/'public').mkdir()
    (root/'public'/'a').write_bytes(b'HEALTHY')
    config = root/'config.kdl'
    source = f'capacity "shared-nat"\nsite "example.com" {{\n root "{root}/public"\n tls "auto"\n publish "/" "a"\n}}\n'
    config.write_text(source)
    process = subprocess.Popen([str(BIN), 'serve-http', str(config), '127.0.0.1:0', '--monitor', '127.0.0.1:0'], stderr=subprocess.PIPE)
    startup = queue.Queue()
    def logs():
        for line in process.stderr:
            event = json.loads(line)
            if event.get('event') == 'listening': startup.put(event)
    threading.Thread(target=logs, daemon=True).start()
    held = []
    try:
        ports = startup.get(timeout=10); port = ports['port']; monitor = ports['monitor_port']
        def metrics():
            with socket.create_connection(('127.0.0.1', monitor), timeout=2) as stream:
                stream.sendall(b'GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n')
                return receive(stream)
        assert b'pathward_admission_global_limit 256\n' in metrics()
        assert b'pathward_admission_peer_limit 192\n' in metrics()
        barrier = threading.Barrier(24)
        def client(_):
            barrier.wait()
            for _ in range(4): assert get(port).endswith(b'HEALTHY')
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            list(pool.map(client, range(24)))
        assert b'pathward_admission_rejected_total 0\n' in metrics()
        # Capacity is immutable until restart. SIGHUP must retain the current state.
        config.write_text(source.replace('capacity "shared-nat"\n', ''))
        process.send_signal(signal.SIGHUP)
        deadline = time.monotonic()+2
        while b'pathward_reload_errors_total 1\n' not in metrics():
            assert time.monotonic()<deadline
            time.sleep(.02)
        assert b'pathward_config_generation 1\n' in metrics()
        assert b'pathward_admission_peer_limit 192\n' in metrics()
        for _ in range(192):
            stream = socket.create_connection(('127.0.0.1', port), timeout=2, source_address=('127.0.0.20',0))
            stream.sendall(b'GET / HTTP/1.1\r\n'); held.append(stream)
        time.sleep(.1)
        with socket.create_connection(('127.0.0.1',port),timeout=2,source_address=('127.0.0.20',0)) as excess:
            assert excess.recv(1)==b''
        started=time.monotonic()
        assert get(port,'127.0.0.21').endswith(b'HEALTHY')
        assert time.monotonic()-started<1.5
        assert b'pathward_admission_rejections_total{reason="peer_active"} 1\n' in metrics()
        print('Shared-NAT capacity passed: 24 clients, fixed reload identity, 192-peer cap and healthy-peer progress.')
    finally:
        for stream in held:stream.close()
        process.terminate()
        try: assert process.wait(timeout=8)==0
        except subprocess.TimeoutExpired: process.kill();process.wait();raise
