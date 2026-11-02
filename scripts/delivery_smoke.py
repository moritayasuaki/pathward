#!/usr/bin/env python3
"""Real sockets: idle/partial heads and slow bodies cannot own ordinary workers."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import hashlib
import json
import queue
import signal
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "server/target/release/pathward-server"
PAYLOAD = b"bounded delivery\n" * (4 * 1024 * 1024 // 17)
created = 0
lock = threading.Lock()
hold_entered, hold_release = threading.Event(), threading.Event()


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/hold":
            hold_entered.set()
            assert hold_release.wait(5)
            payload = b"HELD"
        else:
            payload = PAYLOAD
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        global created
        assert self.rfile.read(int(self.headers["Content-Length"])) == b"one"
        with lock:
            created += 1
        self.send_response(201)
        self.send_header("Content-Length", "2")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"OK")


def head(stream):
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        b = stream.recv(1)
        assert b, data
        data += b
        assert len(data) < 16384
    return data


def finish(stream):
    parts = []
    while True:
        b = stream.recv(65536)
        if not b:
            return b"".join(parts)
        parts.append(b)


upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
threading.Thread(target=upstream.serve_forever, daemon=True).start()
with tempfile.TemporaryDirectory(prefix="pathward-delivery-") as tmp:
    root = Path(tmp)
    config = root / "config.kdl"

    def replace(tag, response_limit="8MiB"):
        pending = root / "pending"
        pending.write_text(f'''capacity "shared-nat"
site "example.com" {{
 tls "auto"
 reverse-proxy "127.0.0.1:{upstream.server_port}"
 proxy-limit "request-body" "1KiB"
 proxy-limit "response-body" "{response_limit}"
 proxy-limit "connections" "2"
 proxy-timeout "total" "15s"
 header "*" "x-robots-tag" "{tag}"
}}
''')
        pending.replace(config)

    replace("old")
    process = subprocess.Popen([str(BINARY), "serve-http", str(config), "127.0.0.1:0",
                                "--monitor", "127.0.0.1:0"], stderr=subprocess.PIPE)
    startup = queue.Queue()
    records = []

    def logs():
        for line in process.stderr:
            event = json.loads(line)
            records.append(event)
            if event.get("event") == "listening":
                startup.put(event)

    threading.Thread(target=logs, daemon=True).start()
    held, downloads = [], []
    try:
        event = startup.get(timeout=10)
        port, monitor = event["port"], event["monitor_port"]

        def connect(p=port):
            return socket.create_connection(("127.0.0.1", p), timeout=3)

        def metrics():
            with connect(monitor) as s:
                s.sendall(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
                head(s)
                return {line.rsplit(" ", 1)[0]: float(line.rsplit(" ", 1)[1])
                        for line in finish(s).decode().splitlines() if line and not line.startswith("#")}

        def post(tag):
            began = time.monotonic()
            with connect() as s:
                s.sendall(b"POST /create HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\none")
                h, body = head(s), finish(s)
                assert h.startswith(b"HTTP/1.1 201 ") and body == b"OK", (h, body)
                assert f"x-robots-tag: {tag}\r\n".encode() in h
            assert time.monotonic() - began < 3, "same-peer API delayed behind socket I/O"

        # Unfinished heads previously occupied both ordinary peer workers.
        for partial in [False, True, False, True]:
            s = connect()
            if partial:
                s.sendall(b"GET / HTTP/1.1\r\n")
            held.append(s)
        post("old")

        # Deliberately keep complete large responses unread, from the same IP.
        for _ in range(24):
            s = connect()
            s.sendall(b"GET /image HTTP/1.1\r\nHost: example.com\r\n\r\n")
            downloads.append(s)
        for s in downloads:
            h = head(s)
            assert h.startswith(b"HTTP/1.1 200 ") and b"x-robots-tag: old\r\n" in h, h
        assert metrics()["pathward_connections_active"] > 4
        post("old")
        replace("new")
        process.send_signal(signal.SIGHUP)
        end = time.monotonic() + 3
        while metrics()["pathward_config_generation"] != 2:
            assert time.monotonic() < end
            time.sleep(.02)
        post("new")
        expected = hashlib.sha256(PAYLOAD).digest()
        with ThreadPoolExecutor(max_workers=24) as executor:
            bodies = list(executor.map(finish, downloads))
        assert all(len(b) == len(PAYLOAD) and hashlib.sha256(b).digest() == expected for b in bodies)
        assert created == 3, "mutation was repeated"
        assert metrics()["pathward_admission_rejected_total"] == 0
        for s in downloads + held:
            s.close()
        held, downloads = [], []

        # A reservation is made before a mutation is sent upstream, and a
        # configuration switch cannot reset outstanding response-byte charges.
        replace("reserved", "64MiB")
        process.send_signal(signal.SIGHUP)
        end = time.monotonic() + 3
        while metrics()["pathward_config_generation"] != 3:
            assert time.monotonic() < end
            time.sleep(.02)
        waiting = connect()
        held.append(waiting)
        waiting.sendall(b"GET /hold HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assert hold_entered.wait(3)
        with connect() as s:
            s.sendall(b"POST /create HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\none")
            assert head(s).startswith(b"HTTP/1.1 503 ")
            finish(s)
        assert created == 3, "rejected mutation reached upstream"
        replace("last")
        process.send_signal(signal.SIGHUP)
        end = time.monotonic() + 3
        while metrics()["pathward_config_generation"] != 4:
            assert time.monotonic() < end
            time.sleep(.02)
        post("last")
        hold_release.set()
        assert b"x-robots-tag: reserved\r\n" in head(waiting)
        assert finish(waiting) == b"HELD"
        assert created == 4
        waiting.close()
        held = []

        # Incomplete input is discarded on shutdown, while delivery is bounded.
        stalled = connect()
        stalled.sendall(b"GET / HTTP/1.1\r\n")
        held.append(stalled)
        before = time.monotonic()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=7) == 0
        assert time.monotonic() - before < 7
        print("Delivery passed: partial headers, 24 slow same-IP bodies, API progress, reload consistency, pre-mutation byte reservation, no retry, bounded shutdown.")
    finally:
        hold_release.set()
        for s in downloads + held:
            s.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
