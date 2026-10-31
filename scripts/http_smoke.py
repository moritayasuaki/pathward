#!/usr/bin/env python3
"""Exercise the release CLI over real HTTP on an ephemeral loopback port."""
from pathlib import Path
import json
import select
import socket
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "server/target/release/pathward-server"
with tempfile.TemporaryDirectory(prefix="pathward-smoke-") as temporary:
    directory = Path(temporary)
    (directory / "public").mkdir()
    (directory / "public/index.html").write_bytes(b"pathward smoke\n")
    config = directory / "Pathward.kdl"
    config.write_text(f'''site "example.com" {{
    root "{directory / 'public'}"
    publish "/" "index.html"
    tls "auto"
}}
''')
    denied = subprocess.run([str(BINARY), "serve-http", str(config), "0.0.0.0:0"],
                            text=True, capture_output=True, timeout=5)
    assert denied.returncode != 0 and "loopback" in denied.stderr
    process = subprocess.Popen([str(BINARY), "serve-http", str(config), "127.0.0.1:0"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        assert select.select([process.stderr], [], [], 10)[0], "server startup timed out"
        line = process.stderr.readline().decode()
        event = json.loads(line)
        assert event["event"] == "listening", event
        port = event["port"]
        for method, path, code, body in [
            ("GET", "/?v=1", 200, b"pathward smoke\n"),
            ("HEAD", "/", 200, b""),
            ("GET", "/index.html", 404, b""),
            ("GET", "/%2e%2e/secret", 404, b""),
            ("POST", "/", 405, b""),
        ]:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as stream:
                stream.sendall(f"{method} {path} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode())
                chunks = []
                while chunk := stream.recv(8192):
                    chunks.append(chunk)
            response = b"".join(chunks)
            head, actual = response.split(b"\r\n\r\n", 1)
            assert head.startswith(f"HTTP/1.1 {code} ".encode()), response
            assert actual == body, response
        print("Release CLI smoke passed: GET, HEAD, query, denial, method, loopback-only binding.")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
