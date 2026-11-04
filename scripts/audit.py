#!/usr/bin/env python3
"""Fail closed on proof holes, extra axioms, dependencies, or missing audit results."""
import argparse
import json
from proof_registry import declarations, audit_source, registry, write_or_check
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROOFS = ROOT / "proofs"
ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-registry", action="store_true")
    args = parser.parse_args()
    entries = declarations()
    write_or_check(PROOFS / "Audit.lean", audit_source(entries), args.write_registry)
    for path in [PROOFS / "Generated/Pathward.lean", *sorted(PROOFS.glob("*Proofs.lean"))]:
        if re.search(r"\b(sorry|admit|axiom|unsafe|native_decide|implemented_by|extern)\b", path.read_text()):
            raise SystemExit(f"Forbidden proof escape in {path.relative_to(ROOT)}")
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--offline", "--locked", "--format-version=1"], cwd=ROOT, text=True))
    if len(metadata["packages"]) != 1 or metadata["packages"][0]["dependencies"]:
        raise SystemExit("The Rust library must have zero external dependencies, including dev/build dependencies")
    output = subprocess.check_output(["lake", "env", "lean", "Audit.lean"], cwd=PROOFS, text=True)
    expected = re.findall(r"^#print axioms ([\w.]+)$", (PROOFS / "Audit.lean").read_text(), re.M)
    seen = set()
    axiom_map = {}
    for name, axioms in re.findall(r"'([\w.]+)' depends on axioms: \[([^\]]*)\]", output):
        actual = {x.strip() for x in axioms.split(",") if x.strip()}
        if not actual <= ALLOWED_AXIOMS:
            raise SystemExit(f"Unexpected axioms for {name}: {actual - ALLOWED_AXIOMS}")
        seen.add(name)
        axiom_map[name] = sorted(actual)
    for name in re.findall(r"'([\w.]+)' does not depend on any axioms", output):
        seen.add(name)
        axiom_map[name] = []
    if len(expected) < 365 or set(expected) != seen:
        raise SystemExit(f"Missing or unexpected axiom audit results: expected {expected}, got {seen}")
    record = registry(entries, axiom_map)
    write_or_check(PROOFS / "registry.json", json.dumps(record, indent=2, ensure_ascii=False) + "\n", args.write_registry)
    print(output, end="")
    print(f"Registry: {record['theorem_count']} named statements; {record['axiom_free_count']} axiom-free; {record['axiom_counts']}")
    print("Audit passed: no proof holes, only standard Lean axioms, zero Rust dependencies.")


if __name__ == "__main__":
    main()
