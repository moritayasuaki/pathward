#!/usr/bin/env python3
"""Explicit, pinned verification-tool setup; uses only the Python standard library."""
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / ".tools"
CACHE = TOOLS / "cache"
HAX = TOOLS / "bin" / "cargo-hax"
AENEAS = CACHE / "hax/tools/aeneas/build-183e4f0"
ARCHIVES = {
    ("Darwin", "arm64"): ("aarch64-apple-darwin", "f5fb1cdb6727310cc0d6aa93ceaa1bddedfbf9d5979438d955130abd52020af4"),
    ("Linux", "x86_64"): ("x86_64-unknown-linux-gnu", "64b15097c003919075c7e8cca845db0e29718c0683596b739677b159ceb138f4"),
    ("Linux", "aarch64"): ("aarch64-unknown-linux-gnu", "6ff3905349417637fc1aac7e88a12467c205903c3ee1215504dd9f705a517db4"),
}


def run(*args, cwd=ROOT, env=None):
    subprocess.run(list(map(str, args)), cwd=cwd, env=env, check=True)


def main():
    for tool in ("curl", "tar", "git", "cargo", "rustup", "elan", "lake"):
        if shutil.which(tool) is None:
            raise SystemExit(f"Missing prerequisite: {tool}. See README.md.")
    key = (platform.system(), platform.machine())
    if key not in ARCHIVES:
        raise SystemExit(f"No pinned verification binary for {key}")
    target, digest = ARCHIVES[key]
    HAX.parent.mkdir(parents=True, exist_ok=True)
    if not HAX.exists():
        with tempfile.TemporaryDirectory(prefix="pathward-setup-") as temporary:
            archive = Path(temporary) / "hax.tar.zst"
            run("curl", "--fail", "--location", "--retry", "3", "--max-time", "600",
                f"https://github.com/cryspen/hax/releases/download/cargo-hax-v0.4.2/cargo-hax-{target}.tar.zst",
                "--output", archive)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
                raise SystemExit("hax archive checksum mismatch")
            # Extract just the reviewed entry point, not arbitrary archive paths.
            run("tar", "-xf", archive, "-C", HAX.parent, "cargo-hax")
    version = subprocess.check_output([str(HAX), "--version"], text=True)
    if "version=0.4.2\n" not in version:
        raise SystemExit("Expected cargo-hax 0.4.2")
    env = dict(os.environ, XDG_CACHE_HOME=str(CACHE), MATHLIB_NO_CACHE_ON_UPDATE="1")
    run(HAX, "tools", "install", env=env)
    run("rustup", "toolchain", "install", "1.98.1", "--profile", "minimal",
        "--component", "rustfmt", "--component", "clippy")
    run("rustup", "toolchain", "install", "nightly-2026-08-18", "--profile", "minimal",
        "--component", "rustc-dev")
    run("elan", "toolchain", "install", "leanprover/lean4:v4.31.0")
    run("lake", "update", cwd=ROOT / "proofs", env=env)
    # Fetch only the Mathlib modules used by the pinned Aeneas library.
    modules = sorted({token for p in (AENEAS / "backends/lean/Aeneas").rglob("*.lean")
                      for line in p.read_text().splitlines() if line.startswith("import ")
                      for token in line.split()[1:] if re.fullmatch(r"Mathlib\.[\w.]+", token)})
    if not modules:
        raise SystemExit("Could not find Aeneas's Mathlib imports")
    run("lake", "exe", "cache", "get", *modules, cwd=ROOT / "proofs", env=env)
    print("Verification tools are ready. Run make check.")


if __name__ == "__main__":
    main()
