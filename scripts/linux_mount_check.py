#!/usr/bin/env python3
"""Run the mount-crossing regression in a private Linux mount namespace (CI only)."""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if sys.platform != "linux":
    raise SystemExit("Mount integration tests require Linux.")
output = subprocess.check_output([
    "cargo", "+1.99.1", "test", "--offline", "--locked", "--manifest-path",
    str(ROOT / "server/Cargo.toml"), "--lib", "--no-run", "--message-format=json"],
    cwd=ROOT, text=True)
executables = [record["executable"] for line in output.splitlines()
               if (record := json.loads(line)).get("reason") == "compiler-artifact"
               and record.get("executable") and record["profile"]["test"]]
if len(executables) != 1:
    raise SystemExit("Expected one server library test executable.")
subprocess.run(["sudo", "-n", "unshare", "--mount", "--propagation", "private",
                executables[0], "--ignored", "--exact", "files::tests::rejects_bind_mounts"],
               cwd=ROOT, check=True)
