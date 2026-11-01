#!/usr/bin/env python3
"""Run the real TLS-ALPN-01 lifecycle against a disposable local Pebble CA."""
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import sys
import subprocess
import tempfile
import threading
import time
import urllib.request
if sys.platform != "linux":
    raise SystemExit("ACME lifecycle integration requires native Linux confinement/storage")
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--soak-seconds", type=int, default=0)
parser.add_argument("--report", default=".tools/soak-latest.json")
parser.add_argument("--rehearsal", action="store_true")
parser.add_argument("--content", type=Path)
parser.add_argument("--manifest", type=Path)
parser.add_argument("--headers", type=Path)
parser.add_argument("--seconds", type=int, default=180)
args = parser.parse_args()
if args.rehearsal and (args.soak_seconds or not args.content or not args.manifest or not 120 <= args.seconds <= 900):
    raise SystemExit("Rehearsal requires --content, --manifest and 120–900 --seconds; no --soak-seconds")
if args.soak_seconds and not 120 <= args.soak_seconds <= 86400:
    raise SystemExit("Soak duration must be 120–86400 seconds")
ROOT = Path(__file__).resolve().parents[1]
PEBBLE = ROOT / ".tools/pebble/pebble"
if not PEBBLE.is_file():
    raise SystemExit("Run make acme-test-setup explicitly first")

def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

with tempfile.TemporaryDirectory(prefix="pathward-acme-integration-") as temporary:
    os.umask(0o077)
    work = Path(temporary)
    # All private keys are ephemeral test keys and never enter the repository.
    with (work / "openssl.log").open("w") as log:
        commands = [
            ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=PathWard Test CA", "-keyout", "ca.key", "-out", "ca.pem"],
            ["req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", "server.key", "-out", "server.csr"],
            ["x509", "-req", "-days", "2", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-extfile", "extensions", "-out", "server.pem"],
        ]
        (work / "extensions").write_text("subjectAltName=DNS:localhost,DNS:stage.pathward.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        for command in commands:
            subprocess.run(["openssl"] + command, cwd=work, stdout=log, stderr=log, check=True)
    api, management, serving = port(), port(), port()
    dns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dns.bind(("127.0.0.1", 0)); dns.listen(32); dns.settimeout(0.2)
    stop = threading.Event()
    def read_exact(connection, size):
        data = b""
        while len(data) < size:
            chunk = connection.recv(size - len(data))
            if not chunk:
                raise OSError("short test DNS frame")
            data += chunk
        return data
    def respond_dns():
        # Pebble's custom resolver deliberately uses DNS over TCP.
        while not stop.is_set():
            try:
                connection, _ = dns.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(1)
                try:
                    size = struct.unpack("!H", read_exact(connection, 2))[0]
                    if size > 4096:
                        continue
                    data = read_exact(connection, size)
                    offset = 12
                    while offset < len(data) and data[offset]:
                        offset += data[offset] + 1
                    end = offset + 5
                    if end > len(data):
                        continue
                    kind = struct.unpack("!H", data[offset+1:offset+3])[0]
                    answer = bytes.fromhex("c00c000100010000000100047f000001") if kind == 1 else b""
                    response = data[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(answer), 0, 0) + data[12:end] + answer
                    connection.sendall(struct.pack("!H", len(response)) + response)
                except OSError:
                    continue
    worker = threading.Thread(target=respond_dns)
    worker.start()
    config = {"pebble": {"listenAddress": f"127.0.0.1:{api}", "managementListenAddress": f"127.0.0.1:{management}",
        "certificate": str(work / "server.pem"), "privateKey": str(work / "server.key"),
        "httpPort": port(), "tlsPort": serving, "keyAlgorithm": "ecdsa",
        "profiles": {"default": {"description": "PathWard local renewal test", "validityPeriod": 60 if args.soak_seconds or args.rehearsal else 30}}}}
    (work / "pebble.json").write_text(json.dumps(config))
    env = dict(os.environ, PEBBLE_VA_NOSLEEP="1", PEBBLE_WFE_NONCEREJECT="0", PEBBLE_AUTHZREUSE="0")
    # Validation is real: deliberately do NOT set PEBBLE_VA_ALWAYS_VALID.
    env.pop("PEBBLE_VA_ALWAYS_VALID", None)
    with (work / "pebble.log").open("w+") as log:
        process = subprocess.Popen([str(PEBBLE), "-config", str(work / "pebble.json"), "-strict=false", "-dnsserver", f"127.0.0.1:{dns.getsockname()[1]}"], env=env, stdout=log, stderr=log)
        try:
            context = ssl.create_default_context(cafile=str(work / "ca.pem"))
            for _ in range(100):
                try:
                    with urllib.request.urlopen(f"https://localhost:{management}/roots/0", context=context, timeout=1) as response:
                        (work / "issued-root.pem").write_bytes(response.read(65536))
                    break
                except (OSError, ValueError):
                    if process.poll() is not None:
                        raise RuntimeError("Pebble exited")
                    time.sleep(0.1)
            else:
                raise RuntimeError("Pebble startup timeout")
            env.update(PATHWARD_TEST_CA=str(work / "ca.pem"), PATHWARD_TEST_ISSUER=str(work / "issued-root.pem"),
                       PATHWARD_TEST_DIRECTORY=f"https://localhost:{api}/dir", PATHWARD_TEST_PORT=str(serving),
                       PATHWARD_TEST_FALLBACK_CERT=str(work / "server.pem"), PATHWARD_TEST_FALLBACK_KEY=str(work / "server.key"))
            command = ([sys.executable, "scripts/soak.py", "--seconds", str(args.soak_seconds), "--report", args.report]
                       if args.soak_seconds else ["cargo", "+1.99.1", "test", "--offline", "--locked", "--manifest-path", "server/Cargo.toml", "--test", "acme_lifecycle", "--", "--ignored", "--nocapture"])
            if args.rehearsal:
                command = [sys.executable, "scripts/staging_rehearsal.py", "--content", str(args.content.resolve()),
                           "--manifest", str(args.manifest.resolve()), "--seconds", str(args.seconds), "--report", args.report]
                if args.headers:
                    command += ["--headers", str(args.headers.resolve())]
            subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=(args.seconds if args.rehearsal else args.soak_seconds) + 300)
        except Exception:
            log.flush(); log.seek(0)
            print(log.read()[-20000:])  # Pebble protocol diagnostics only, never key material.
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
            stop.set(); worker.join(timeout=2); dns.close()
print("Isolated migration rehearsal passed" if args.rehearsal else "Local ACME soak passed" if args.soak_seconds else "Real local ACME issuance, TLS-ALPN-01, renewal and restart passed")
