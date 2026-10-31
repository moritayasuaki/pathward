#!/usr/bin/env python3
"""Bounded Linux soak using the real server, private control socket and local ACME.

Invoked by acme_integration.py; no external Python packages or public CA traffic.
Reports contain counters/public certificate fingerprints, never keys or content.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import re
import signal
import socket
import ssl
import statistics
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "server/target/release/pathward-server"
DRIVER = ROOT / "server/target/release/examples/soak_server"
HOSTS = ("one.pathward.test", "two.pathward.test")
BUCKETS = (5, 10, 25, 50, 100, 250, 500, 1000, 2000, 3000, 10000)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--seconds", type=int, required=True)
parser.add_argument("--report", type=Path, required=True)
args = parser.parse_args()
assert 120 <= args.seconds <= 86400
stop = threading.Event()
lock = threading.Lock()
counts = collections.Counter()
latencies = [0] * len(BUCKETS)
certificates = set()
resources = []
failures = []
order_active = False
measuring = False
started = None
process = None

def fail(message):
    with lock:
        if len(failures) < 10:
            failures.append(message)
    stop.set()

def counted(name, amount=1):
    with lock:
        counts[name] += amount

def command(control, action="STATUS", expected=None, data=b"", allow_reject=False):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(str(control / "control.sock"))
        if action == "STATUS":
            frame = b"STATUS\n"
        else:
            generation, digest = expected
            frame = f"{action} {generation} {digest} {len(data)}\n".encode() + data
        stream.sendall(frame)
        reply = b""
        while not reply.endswith(b"\n") and len(reply) < 160:
            chunk = stream.recv(160 - len(reply))
            if not chunk:
                break
            reply += chunk
    if allow_reject and reply == b"ERR\n":
        return None
    fields = reply.decode().strip().split(" ")
    assert len(fields) == 3 and fields[0] == "OK", "control reply rejected"
    assert re.fullmatch("[0-9a-f]{64}", fields[2]), "invalid revision"
    return int(fields[1]), fields[2]

def response(port, request, context=None, host=HOSTS[0], peer="127.0.0.20"):
    began = time.monotonic()
    stream = socket.create_connection(("127.0.0.1", port), timeout=3, source_address=(peer, 0))
    fingerprint = None
    try:
        if context:
            stream = context.wrap_socket(stream, server_hostname=host)
            fingerprint = hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest()
        stream.sendall(request)
        output = b""
        while chunk := stream.recv(8192):
            output += chunk
            assert len(output) <= 100_000, "response exceeded test bound"
        head, body = output.split(b"\r\n\r\n", 1)
        lines = head.decode("ascii").split("\r\n")
        code = int(lines[0].split(" ")[1])
        headers = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            assert name.lower() not in headers, "duplicate response header"
            headers[name.lower()] = value.strip()
        return code, headers, body, fingerprint, (time.monotonic() - began) * 1000
    finally:
        stream.close()

def request(method, target, host=HOSTS[0]):
    return f"{method} {target} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()

def payload(host, release):
    return (f"PUBLIC:{host}:{release}:".encode() * 3000)[:65536]

def config(root, release):
    name = "a" if release == "A" else "b"
    return "".join(
        f'site "{host}" {{\nroot "{root/release/host}"\ntls "auto"\npublish "/" "{name}"\npublish "/{name}" "{name}"\nredirect "/legacy" "{host}" "/{name}" "308"\nheader "*" "x-robots-tag" "release-{release}"\nheader "*" "strict-transport-security" "max-age=60"\n}}\n'
        for host in HOSTS
    ).encode()

def start_driver(control, cache):
    p = subprocess.Popen([str(DRIVER), str(control), str(cache), os.environ["PATHWARD_TEST_DIRECTORY"],
                          os.environ["PATHWARD_TEST_CA"], os.environ["PATHWARD_TEST_PORT"]],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    startup = queue.Queue()
    def stdout():
        for line in p.stdout:
            startup.put(json.loads(line))
    def logs():
        global order_active
        for line in p.stderr:
            try:
                event = json.loads(line)["event"]
            except (ValueError, KeyError):
                fail("non-JSON driver error")
                continue
            with lock:
                if event == "acme_order_started":
                    order_active = True
                if event == "reload_committed" and order_active and measuring:
                    counts["commits_during_acme_order"] += 1
                if event in ("acme_activated", "acme_failed"):
                    order_active = False
                if measuring:
                    counts["event_" + event] += 1
            if measuring and event in ("acme_failed", "certificate_unavailable", "deployment_recovery_failed"):
                fail(event)
    threading.Thread(target=stdout, daemon=True).start()
    threading.Thread(target=logs, daemon=True).start()
    try:
        ports = startup.get(timeout=15)
    except BaseException:
        p.kill(); p.wait(timeout=5)
        raise
    return p, ports

def metrics(port):
    code, _, body, _, _ = response(port, request("GET", "/metrics", "localhost"))
    assert code == 200
    return {line.split()[0]: float(line.split()[1]) for line in body.decode().splitlines()
            if line and not line.startswith("#")}

def sample(pid):
    status = Path(f"/proc/{pid}/status").read_text()
    rss = int(re.search(r"^VmRSS:\s+(\d+)", status, re.M)[1])
    threads = int(re.search(r"^Threads:\s+(\d+)", status, re.M)[1])
    return {"elapsed": round(time.monotonic()-started, 2), "rss_kib": rss,
            "threads": threads, "fds": len(list(Path(f"/proc/{pid}/fd").iterdir()))}

def report(state, extra=None):
    with lock:
        data = {"state": state, "requested_seconds": args.seconds,
                "elapsed_seconds": round(time.monotonic()-started, 3) if started else 0,
                "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "platform": platform.platform(), "counters": dict(counts),
                "latency_bucket_upper_ms": list(BUCKETS), "latency_bucket_counts": latencies.copy(),
                "distinct_certificates": len(certificates), "failures": failures.copy()}
        if resources:
            data["resources"] = {field: {"min": min(s[field] for s in resources),
                                          "max": max(s[field] for s in resources), "last": resources[-1][field]}
                                 for field in ("rss_kib", "threads", "fds")}
            warm = [s["rss_kib"] for s in resources if 20 <= s["elapsed"] <= 40]
            end = [s["rss_kib"] for s in resources[-10:]]
            if warm:
                data["rss_growth_kib"] = statistics.median(end) - statistics.median(warm)
    if extra:
        data.update(extra)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    pending = args.report.with_suffix(".pending")
    pending.write_text(json.dumps(data, indent=2)+"\n")
    pending.replace(args.report)
    return data

try:
    with tempfile.TemporaryDirectory(prefix="pathward-soak-") as temporary:
        root = Path(temporary)
        for release in ("A", "B"):
            for host in HOSTS:
                directory = root / release / host
                directory.mkdir(parents=True)
                for name in ("a", "b"):
                    value = payload(host, release) if name == ("a" if release == "A" else "b") else b"FORBIDDEN_MIXED_ROOT"
                    (directory/name).write_bytes(value)
                (directory/"secret").write_bytes(b"FORBIDDEN_SECRET")
        configs = {release: config(root, release) for release in ("A", "B")}
        digests = {hashlib.sha256(value).hexdigest(): release for release, value in configs.items()}
        initial = root / "initial.kdl"
        initial.write_bytes(configs["A"])
        control, cache = root / "control", root / "cache"
        subprocess.run([str(BIN), "init", str(control), str(initial)], check=True, capture_output=True)
        context = ssl.create_default_context(cafile=os.environ["PATHWARD_TEST_ISSUER"])
        context.set_alpn_protocols(["http/1.1"])
        process, ports = start_driver(control, cache)
        deadline = time.monotonic()+90
        while True:
            if stop.is_set() or process.poll() is not None:
                raise RuntimeError("driver failed during initial issuance")
            try:
                first = response(ports["tls"], request("GET", "/"), context)
                assert first[0] == 200 and first[2] == payload(HOSTS[0], "A")
                break
            except (OSError, ValueError):
                if time.monotonic() > deadline:
                    raise RuntimeError("initial certificate timeout")
                time.sleep(.25)
        account = (cache / ".account").read_bytes()
        started = time.monotonic()
        measuring = True
        certificates.add(first[3])
        def load(number):
            iteration = 0
            stop.wait(number*.0625)
            while not stop.is_set():
                began = time.monotonic()
                host = HOSTS[(iteration//8) % 2]
                case = iteration % 8
                target = ["/", "/", "/legacy?q=%0d%0a", "/secret", "/%2e%2e/secret", "/", "/", "/?q=raw%20bytes"][case]
                method = "HEAD" if case == 1 else "GET"
                authority = HOSTS[1] if case == 5 and host == HOSTS[0] else (HOSTS[0] if case == 5 else host)
                plain = case == 6
                try:
                    code, headers, body, fingerprint, elapsed = response(
                        ports["http"] if plain else ports["tls"], request(method, target, authority),
                        None if plain else context, host, f"127.0.0.{10+number}")
                    if plain:
                        assert code == 308 and headers["location"] == f"https://{host}{target}"
                        assert "strict-transport-security" not in headers and body == b""
                    elif case == 5:
                        assert code == 421 and body == b""
                    elif case in (3, 4):
                        assert code == 404 and body == b""
                    else:
                        release = headers["x-robots-tag"].removeprefix("release-")
                        assert release in configs and headers["strict-transport-security"] == "max-age=60"
                        expected = payload(host, release)
                        if case == 2:
                            name = "a" if release == "A" else "b"
                            assert code == 308 and headers["location"] == f"https://{host}/{name}?q=%0d%0a" and body == b""
                        else:
                            assert code == 200 and int(headers["content-length"]) == len(expected)
                            assert body == (b"" if method == "HEAD" else expected), "mixed generation/content"
                    assert b"FORBIDDEN_" not in body, "unpublished content leaked"
                    with lock:
                        counts["requests_ok"] += 1
                        counts["negative_requests"] += case in (3, 4, 5)
                        if fingerprint:
                            certificates.add(fingerprint)
                        for i, upper in enumerate(BUCKETS):
                            if elapsed <= upper:
                                latencies[i] += 1
                                break
                        else:
                            raise AssertionError("latency exceeded bound")
                except BaseException as error:
                    counted("request_failures")
                    fail(f"load {number} case {case}: {type(error).__name__}: {str(error)[:120]}")
                    return
                iteration += 1
                stop.wait(max(0, .25-(time.monotonic()-began)))
        def slow_peer():
            while not stop.is_set():
                held = []
                try:
                    for i in range(6):
                        port = ports["tls"] if i % 2 else ports["http"]
                        stream = socket.create_connection(("127.0.0.1", port), timeout=2, source_address=("127.0.0.2", 0))
                        stream.sendall(b"\x16\x03\x01" if i % 2 else b"GET / HTTP/1.1\r\n")
                        held.append(stream)
                    counted("slow_connection_cycles")
                    stop.wait(1.5)
                except OSError:
                    # These adversarial peers may be refused by the admission gate.
                    counted("slow_connections_refused")
                finally:
                    for stream in held:
                        stream.close()
                stop.wait(.15)
        def switches():
            turn = 0
            while not stop.is_set():
                began = time.monotonic()
                try:
                    previous = command(control)
                    current = digests[previous[1]]
                    candidate = configs["B" if current == "A" else "A"]
                    action = "ROLLBACK" if turn % 4 == 3 else "APPLY"
                    data = b"" if action == "ROLLBACK" else candidate
                    result = command(control, action, previous, data, allow_reject=True)
                    if result:
                        assert result[0] > previous[0] and result[1] in digests
                        if action == "APPLY":
                            assert result[1] == hashlib.sha256(data).hexdigest()
                        counted("config_commits")
                        if action == "ROLLBACK": counted("rollbacks")
                    else:
                        counted("concurrent_rejections")
                    if turn % 5 == 0:
                        now = command(control)
                        assert command(control, "APPLY", (0, now[1]), candidate, True) is None
                        assert command(control) == now
                        counted("stale_rejections")
                        invalid = candidate.replace(str(root / ("B" if current == "A" else "A") / HOSTS[0]).encode(), str(control).encode())
                        assert command(control, "APPLY", now, invalid, True) is None
                        assert command(control) == now
                        counted("unsafe_root_rejections")
                    if turn % 11 == 0:
                        os.kill(process.pid, signal.SIGHUP)
                        counted("sighups")
                    turn += 1
                except BaseException as error:
                    fail(f"switch: {type(error).__name__}: {str(error)[:120]}")
                    return
                stop.wait(max(0, 1-(time.monotonic()-began)))
        threads = [threading.Thread(target=load, args=(i,)) for i in range(4)]
        threads += [threading.Thread(target=slow_peer), threading.Thread(target=switches)]
        for worker in threads: worker.start()
        next_report = started
        last_metrics = None
        try:
            while time.monotonic()-started < args.seconds and not stop.is_set():
                assert process.poll() is None, "server process exited"
                m = metrics(ports["monitor"])
                assert m["pathward_ready"] == 1, "readiness lost during overlap"
                assert m["pathward_certificate_not_after_seconds"] > time.time(), "expired certificate"
                assert m["pathward_connections_active"] <= 4
                assert m["pathward_acme_errors_total"] == 0
                assert m["pathward_log_dropped_total"] == 0
                r = sample(process.pid)
                assert r["rss_kib"] <= 131072 and r["threads"] <= 32 and r["fds"] <= 128, "resource ceiling"
                with lock: resources.append(r)
                last_metrics = m
                if time.monotonic() >= next_report:
                    snapshot = report("running")
                    assert snapshot.get("rss_growth_kib", 0) <= 16384, "RSS growth exceeded 16 MiB"
                    print(json.dumps({k: snapshot[k] for k in ("state", "elapsed_seconds", "counters", "distinct_certificates", "resources")}), flush=True)
                    next_report = time.monotonic()+60
                stop.wait(2)
        finally:
            stop.set()
            for worker in threads: worker.join(timeout=10)
        assert not failures, failures
        assert all(not worker.is_alive() for worker in threads), "test thread did not stop"
        assert counts["requests_ok"] >= args.seconds * 10, "offered load fell below 10 completed requests/s"
        assert counts["config_commits"] >= args.seconds*.7, "configuration churn stalled"
        assert counts["rollbacks"] >= args.seconds*.15
        assert counts["commits_during_acme_order"] >= 2, "ACME and commits did not overlap"
        assert len(certificates) >= max(3, args.seconds//60), "too few observed renewed certificates"
        assert (cache / ".account").read_bytes() == account, "account unexpectedly replaced"
        for directory, files in [(cache, (".account", ".certificate")), (control, (".config", ".previous"))]:
            assert directory.stat().st_mode & 0o7777 == 0o700
            for name in files:
                stat = (directory/name).stat()
                assert stat.st_mode & 0o7777 == 0o600 and stat.st_nlink == 1
        measuring = False
        shutdown_started = time.monotonic()
        process.terminate()
        assert process.wait(timeout=12) == 0, "graceful stop failed"
        shutdown_seconds = time.monotonic()-shutdown_started
        durable = (cache / ".certificate").read_text()
        public = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", durable, re.S)[0]
        persisted = hashlib.sha256(ssl.PEM_cert_to_DER_cert(public)).hexdigest()
        stop.clear()
        process, ports = start_driver(control, cache)
        restarted = response(ports["tls"], request("GET", "/"), context)
        assert restarted[3] == persisted, "restart did not reuse durable certificate"
        assert restarted[2] == payload(HOSTS[0], digests[command(control)[1]])
        assert (cache / ".account").read_bytes() == account
        process.terminate()
        assert process.wait(timeout=12) == 0
        process = None
        result = report("passed", {"shutdown_seconds": round(shutdown_seconds, 3),
                                  "restart_reused_certificate": True, "account_reused": True,
                                  "final_metrics": last_metrics})
        print("SOAK_RESULT " + json.dumps(result, sort_keys=True), flush=True)
except BaseException as error:
    fail(f"main: {type(error).__name__}: {str(error)[:200]}")
    report("failed")
    raise
finally:
    stop.set()
    if process is not None and process.poll() is None:
        process.terminate()
        try: process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)
