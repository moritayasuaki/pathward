#!/usr/bin/env python3
"""Fail closed on proof holes, extra axioms, dependencies, or missing audit results."""
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROOFS = ROOT / "proofs"
ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


def main():
    for path in [PROOFS / "Generated/Pathward.lean", PROOFS / "PathwardProofs.lean", PROOFS / "RulesProofs.lean", PROOFS / "ServingProofs.lean", PROOFS / "TlsProofs.lean", PROOFS / "RuntimeProofs.lean", PROOFS / "ResponseProofs.lean", PROOFS / "ReleaseProofs.lean", PROOFS / "ProxyProofs.lean", PROOFS / "RoutingProofs.lean", PROOFS / "StreamingProofs.lean"]:
        if re.search(r"\b(sorry|admit|axiom|unsafe|native_decide|implemented_by|extern)\b", path.read_text()):
            raise SystemExit(f"Forbidden proof escape in {path.relative_to(ROOT)}")
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--offline", "--locked", "--format-version=1"], cwd=ROOT, text=True))
    if len(metadata["packages"]) != 1 or metadata["packages"][0]["dependencies"]:
        raise SystemExit("The Rust library must have zero external dependencies, including dev/build dependencies")
    output = subprocess.check_output(["lake", "env", "lean", "Audit.lean"], cwd=PROOFS, text=True)
    expected = re.findall(r"^#print axioms ([\w.]+)$", (PROOFS / "Audit.lean").read_text(), re.M)
    seen = set()
    for name, axioms in re.findall(r"'([\w.]+)' depends on axioms: \[([^\]]*)\]", output):
        actual = {x.strip() for x in axioms.split(",") if x.strip()}
        if not actual <= ALLOWED_AXIOMS:
            raise SystemExit(f"Unexpected axioms for {name}: {actual - ALLOWED_AXIOMS}")
        seen.add(name)
    for name in re.findall(r"'([\w.]+)' does not depend on any axioms", output):
        seen.add(name)
    if len(expected) < 221 or set(expected) != seen:
        raise SystemExit(f"Missing or unexpected axiom audit results: expected {expected}, got {seen}")
    print(output, end="")
    print("Audit passed: no proof holes, only standard Lean axioms, zero Rust dependencies.")


if __name__ == "__main__":
    main()
