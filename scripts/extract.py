#!/usr/bin/env python3
"""Re-extract the actual Rust entry point; fail on stale or unsupported output."""
import argparse
import difflib
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / ".tools/cache/hax/tools"
CHARON = TOOLS / "charon/nightly-2026.09.02/charon"
AENEAS = TOOLS / "aeneas/build-183e4f0/aeneas"
MODEL = ROOT / "proofs/Generated/Pathward.lean"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare without modifying the committed model")
    args = parser.parse_args()
    if not CHARON.is_file() or not AENEAS.is_file():
        raise SystemExit("Verification tools are missing; run make setup first.")
    version = subprocess.check_output([str(AENEAS), "-version"], text=True).strip()
    if version != "aeneas build-183e4f0":
        raise SystemExit(f"Unexpected Aeneas version: {version}")
    with tempfile.TemporaryDirectory(prefix="pathward-extract-") as temporary:
        output = Path(temporary)
        llbc = output / "pathward.llbc"
        subprocess.run([str(CHARON), "cargo", "--preset=aeneas", "--sysroot", "default",
                        "--start-from", "pathward::is_public", "--dest-file", str(llbc)],
                       cwd=ROOT, check=True)
        subprocess.run([str(AENEAS), "-backend", "lean", "-loops-to-rec", "-no-progress-bar",
                        "-abort-on-error", "-warnings-as-errors", "-dest", str(output), str(llbc)],
                       cwd=ROOT, check=True)
        generated = (output / "Pathward.lean").read_text()
        if re.search(r"\b(sorry|admit|axiom|opaque)\b", generated):
            raise SystemExit("Extraction contains an unverified placeholder or external declaration")
        if args.check:
            committed = MODEL.read_text()
            if committed != generated:
                print("".join(difflib.unified_diff(committed.splitlines(True), generated.splitlines(True),
                                                 fromfile="committed model", tofile="current Rust extraction")))
                raise SystemExit("Stale Lean extraction. Run make extract and update the proofs.")
        else:
            MODEL.parent.mkdir(parents=True, exist_ok=True)
            MODEL.write_text(generated)
    print("Rust extraction matches the committed model." if args.check else "Rust model extracted.")


if __name__ == "__main__":
    main()
