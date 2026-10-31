#!/usr/bin/env python3
"""One slow peer must not occupy every worker; run against the release CLI."""
from pathlib import Path
import json
import queue
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "server/target/release/pathward-server"
with tempfile.TemporaryDirectory(prefix="pathward-fairness-") as temporary:
    root = Path(temporary)
    (root / "a").write_text("HEALTHY")
    config = root / "config.kdl"
    config.write_text(f'site "example.com" {{\nroot "{root}"\npublish "/" "a"\ntls "auto"\n}}')
    process = subprocess.Popen([str(BINARY), "serve-http", str(config), "127.0.0.1:0"], stderr=subprocess.PIPE)
    startup = queue.Queue()
    def logs():
        for line in process.stderr:
            event = json.loads(line)
            if event["event"] == "listening":
                startup.put(event)
    threading.Thread(target=logs, daemon=True).start()
    held = []
    try:
        port = startup.get(timeout=10)["port"]
        for _ in range(6):
            stream = socket.create_connection(("127.0.0.1", port), timeout=2, source_address=("127.0.0.2", 0))
            stream.sendall(b"GET / HTTP/1.1\r\n")
            held.append(stream)
        time.sleep(.15)
        started = time.monotonic()
        with socket.create_connection(("127.0.0.1", port), timeout=1.5, source_address=("127.0.0.3", 0)) as stream:
            stream.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            response = b""
            while chunk := stream.recv(8192):
                response += chunk
        assert response.endswith(b"HEALTHY"), response
        assert time.monotonic() - started < 1.5
        print("Worker fairness passed: six slow connections cannot starve another peer.")
    finally:
        for stream in held:
            stream.close()
        process.terminate()
        try:
            assert process.wait(timeout=8) == 0
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
