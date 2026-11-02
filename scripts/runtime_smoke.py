#!/usr/bin/env python3
"""Linux release CLI: real signals, transactional reload, bounded drain and telemetry."""
from pathlib import Path
import json
import os
import queue
import signal
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "server/target/release/pathward-server"

def response(stream):
    chunks = []
    while True:
        try:
            part = stream.recv(8192)
        except ConnectionResetError:
            break
        if not part:
            break
        chunks.append(part)
    return b"".join(chunks)

def get(port, path="/", host="example.com", method="GET"):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as stream:
        stream.sendall(f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        return response(stream)

def wait_for(check, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.03)
    raise AssertionError("condition timed out")

with tempfile.TemporaryDirectory(prefix="pathward-runtime-") as temporary:
    directory = Path(temporary)
    for name in ("old", "new"):
        (directory / name).mkdir()
        (directory / name / "index.html").write_text(name.upper())
    config = directory / "Pathward.kdl"
    def content(root, host="example.com", path="/"):
        return f'site "{host}" {{\nroot "{root}"\npublish "{path}" "index.html"\nredirect "/legacy" "example.com" "/new" "308"\nheader "*" "referrer-policy" "no-referrer"\nheader "/new" "referrer-policy" "same-origin"\ntls "auto"\n}}\n'
    def replace(text):
        pending = directory / "pending"
        pending.write_text(text)
        pending.replace(config)
    def start():
        process = subprocess.Popen([str(BINARY),"serve-http",str(config),"127.0.0.1:0","--monitor","127.0.0.1:0"],stderr=subprocess.PIPE,stdout=subprocess.DEVNULL)
        records = []
        startup = queue.Queue()
        def logs():
            for line in process.stderr:
                record = json.loads(line)
                records.append(record)
                if record.get("event") == "listening":
                    startup.put(record)
        reader = threading.Thread(target=logs,daemon=True)
        reader.start()
        event = startup.get(timeout=10)
        return process,event["port"],event["monitor_port"],records,reader
    replace(content(directory / "old"))
    # Public monitoring is refused before serving begins.
    denied = subprocess.run([str(BINARY),"serve-http",str(config),"127.0.0.1:0","--monitor","0.0.0.0:0"],capture_output=True,timeout=5)
    assert denied.returncode and b"loopback" in denied.stderr
    process,port,monitor,records,reader = start()
    def metrics():
        result = get(monitor,"/metrics").split(b"\r\n\r\n",1)[1].decode()
        return {line.split()[0]:float(line.split()[1]) for line in result.splitlines() if line and not line.startswith("#")}
    try:
        wait_for(lambda: get(monitor,"/readyz").startswith(b"HTTP/1.1 200"))
        assert get(monitor,"/healthz").endswith(b"ok\n")
        assert get(monitor,"/metrics",method="POST").startswith(b"HTTP/1.1 405")
        assert get(port).endswith(b"OLD")
        replace(content(directory / "new",path="/new"))
        process.send_signal(signal.SIGHUP)
        wait_for(lambda: metrics()["pathward_config_generation"]==2)
        assert get(port).startswith(b"HTTP/1.1 404")
        new=get(port,"/new?PRIVATE_QUERY_TOKEN=123")
        assert new.endswith(b"NEW") and b"referrer-policy: same-origin\r\n" in new
        redirect=get(port,"/legacy?q=kept")
        assert redirect.startswith(b"HTTP/1.1 308") and b"Location: https://example.com/new?q=kept\r\n" in redirect
        assert b"referrer-policy: no-referrer\r\n" in redirect
        assert get(port,"/legacy",host="evil.test").startswith(b"HTTP/1.1 421")
        for text in ["broken kdl {", content(directory/"missing",path="/new"), content(directory/"old",host="other.example")]:
            before = metrics()["pathward_reload_errors_total"]
            replace(text)
            process.send_signal(signal.SIGHUP)
            wait_for(lambda: metrics()["pathward_reload_errors_total"] > before)
            assert metrics()["pathward_config_generation"]==2
            assert get(port,"/new").endswith(b"NEW")
        # FIFO reload must fail promptly without stalling the reload worker.
        config.unlink()
        os.mkfifo(config)
        before=metrics()["pathward_reload_errors_total"]
        process.send_signal(signal.SIGHUP)
        wait_for(lambda: metrics()["pathward_reload_errors_total"] > before)
        replace(content(directory/"new",path="/new"))
        process.send_signal(signal.SIGHUP)
        wait_for(lambda: metrics()["pathward_config_generation"]==3)
        # Header collection no longer occupies ordinary workers. On shutdown,
        # discard unfinished inputs and never forward their partial requests.
        wait_for(lambda: metrics()["pathward_connections_active"]==0)
        active = [socket.create_connection(("127.0.0.1",port),timeout=3) for _ in range(4)]
        for stream in active: stream.sendall(b"GET /new HTTP/1.1\r\nHost: example.com\r\n")
        wait_for(lambda: metrics()["pathward_connections_active"]==4)
        # A complete request from the same peer can progress beside the partial head.
        assert get(port,"/new").endswith(b"NEW")
        process.send_signal(signal.SIGTERM)
        for stream in active:
            assert response(stream).startswith(b"HTTP/1.1 408 ")
            stream.close()
        assert process.wait(timeout=5)==0
        reader.join(timeout=2)
        assert any(r["event"]=="reload_committed" for r in records)
        assert any(r["event"]=="draining" for r in records)
        assert all("PRIVATE_QUERY_TOKEN" not in json.dumps(r) for r in records)
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=5)
    # SIGINT also drains; an unfinished request cannot keep the process alive.
    process,port,monitor,records,reader = start()
    try:
        stream=socket.create_connection(("127.0.0.1",port),timeout=8)
        stream.sendall(b"GET /new HTTP/1.1\r\n")
        wait_for(lambda: metrics()["pathward_connections_active"]==1)
        assert get(port,"/new").endswith(b"NEW")
        started=time.monotonic()
        process.send_signal(signal.SIGINT)
        assert response(stream).startswith(b"HTTP/1.1 408")
        stream.close()
        assert process.wait(timeout=3)==0
        assert time.monotonic()-started<7
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=5)
print("Runtime CLI passed: atomic reload/rejection/FIFO, SIGTERM/SIGINT, incomplete-input discard/deadline, health/metrics/redacted JSON logs.")
