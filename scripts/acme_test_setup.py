#!/usr/bin/env python3
"""Explicit installation of the pinned local-only Pebble test CA (not shipped)."""
import hashlib
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
ROOT = Path(__file__).resolve().parents[1]
ASSETS = {
    ("Linux", "x86_64"): ("linux-amd64", "4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed"),
    ("Darwin", "arm64"): ("darwin-arm64", "09a3a4e6ebed71e8d83294a26d361232262f45a7488f5de7bccb5887b395217f"),
}
name, expected = ASSETS[(platform.system(), platform.machine())]
destination = ROOT / ".tools/pebble/pebble"
destination.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="pathward-pebble-setup-") as temporary:
    archive = Path(temporary) / "pebble.tar.gz"
    subprocess.run(["curl", "--fail", "--location", "--retry", "3", "--max-time", "180",
                    f"https://github.com/letsencrypt/pebble/releases/download/v2.10.1/pebble-{name}.tar.gz",
                    "--output", str(archive)], check=True)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise SystemExit("Pebble archive checksum mismatch")
    with tarfile.open(archive) as tar:
        members = [m for m in tar.getmembers() if m.name.split("/")[-1] == "pebble" and m.isfile()]
        if len(members) != 1:
            raise SystemExit("Unexpected Pebble archive layout")
        destination.write_bytes(tar.extractfile(members[0]).read())
    destination.chmod(0o755)
print("Installed pinned Pebble v2.10.1 for local-only integration tests")
