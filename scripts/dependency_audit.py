#!/usr/bin/env python3
"""Check the reviewed dependency graph and scan every locked package with RustSec."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "audit/server-stack"
PROFILES = {"server_candidate": FIXTURE, "configuration": ROOT / "config", "http_server": ROOT / "server"}
AUDITOR = ROOT / ".tools/audit/bin/cargo-audit"
AUDITOR_VERSION = "cargo-audit 0.22.2"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def output(*args, cwd=ROOT):
    return subprocess.check_output(list(map(str, args)), cwd=cwd, text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def graph_snapshot(metadata, directory=FIXTURE):
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    packages = []
    for package in metadata["packages"]:
        if package["id"] == metadata["resolve"]["root"]:
            continue
        source = package["source"]
        local = {(ROOT / "Cargo.toml").resolve(): "path:.",
                 (ROOT / "config/Cargo.toml").resolve(): "path:config",
                 (ROOT / "vendor/rustls-acme/Cargo.toml").resolve(): "path:vendor/rustls-acme"}
        if source is None:
            source = local.get(Path(package["manifest_path"]).resolve())
        if source not in (REGISTRY, "path:.", "path:config", "path:vendor/rustls-acme"):
            raise SystemExit(f"Unreviewed package source: {package['name']} {package['source']}")
        packages.append({
            "name": package["name"], "version": package["version"],
            "source": source, "license": package["license"],
            "features": sorted(nodes[package["id"]]["features"]),
            "build_script": any("custom-build" in target["kind"] for target in package["targets"]),
            "proc_macro": any("proc-macro" in target["kind"] for target in package["targets"]),
        })
    result = {
        "manifest_sha256": digest(directory / "Cargo.toml"),
        "lockfile_sha256": digest(directory / "Cargo.lock"),
        "packages": sorted(packages, key=lambda package: (package["name"], package["version"])),
    }
    if any(p["source"] == "path:vendor/rustls-acme" for p in packages):
        vendor = ROOT / "vendor/rustls-acme"
        result["vendor_files_sha256"] = {str(p.relative_to(vendor)): digest(p)
                                        for p in sorted(vendor.rglob("*")) if p.is_file()}
    return result


def scan(database, lockfile, expected_count):
    command = [str(AUDITOR), "audit", "--file", str(lockfile), "--db", str(database),
               "--no-fetch", "--deny", "warnings", "--json"]
    process = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if process.stderr:
        print(process.stderr, end="")
    try:
        report = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit(f"Missing audit results: {process.stdout}") from error
    settings = report["settings"]
    if (process.returncode or report["vulnerabilities"]["found"] or report["warnings"] or
            settings["ignore"] or settings["target_arch"] or settings["target_os"] or
            settings["severity"] is not None or
            not {"unmaintained", "unsound", "notice"} <= set(settings["informational_warnings"]) or
            report["database"]["advisory-count"] <= 0 or
            report["lockfile"]["dependency-count"] != expected_count):
        print(json.dumps(report, indent=2))
        raise SystemExit("Dependency audit failed; resolve findings without blanket exceptions.")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path,
                        help="use this existing RustSec checkout (no DB fetch; yanked checks still use the network)")
    args = parser.parse_args()
    if not AUDITOR.is_file():
        raise SystemExit("Missing cargo-audit. Run make dependency-audit-setup explicitly.")
    if output(AUDITOR, "--version") != AUDITOR_VERSION:
        raise SystemExit(f"Expected {AUDITOR_VERSION}")
    # Network fetch is explicit; --locked prevents silent dependency changes.
    graphs = {}
    for name, directory in PROFILES.items():
        cargo = ["cargo", "+1.99.1"] if name == "http_server" else ["cargo"]
        metadata = json.loads(output(*cargo, "metadata", "--locked", "--format-version=1",
                                    "--manifest-path", directory / "Cargo.toml"))
        graph = graph_snapshot(metadata, directory)
        if graph != json.loads((directory / "reviewed-graph.json").read_text()):
            raise SystemExit(f"{name}: dependency graph or features changed. Review the diff and refresh the audit record first.")
        graphs[name] = graph
    core = json.loads(output("cargo", "metadata", "--locked", "--offline", "--format-version=1"))
    if len(core["packages"]) != 1 or core["packages"][0]["dependencies"]:
        raise SystemExit("The proved core must stay dependency-free; review server dependencies separately.")
    with tempfile.TemporaryDirectory(prefix="pathward-rustsec-") as temporary:
        database = args.db.resolve() if args.db else Path(temporary) / "advisory-db"
        if args.db is None:
            subprocess.run(["git", "clone", "--depth=1", "https://github.com/RustSec/advisory-db.git",
                            str(database)], check=True)
        if output("git", "status", "--porcelain", cwd=database):
            raise SystemExit("RustSec checkout has local changes; use a clean official database.")
        revision = output("git", "rev-parse", "HEAD", cwd=database)
        reports = {"core": scan(database, ROOT / "Cargo.lock", 1)}
        for name, directory in PROFILES.items():
            reports[name] = scan(database, directory / "Cargo.lock", len(graphs[name]["packages"]) + 1)
        result = {
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "auditor": AUDITOR_VERSION, "database_commit": revision,
            "profiles": {name: {key: graph[key] for key in ("manifest_sha256", "lockfile_sha256", "vendor_files_sha256") if key in graph}
                         for name, graph in graphs.items()},
            "rustc": output("rustc", "--version"),
            "server_rustc": output("rustc", "+1.99.1", "--version"), "reports": reports,
        }
    destination = ROOT / ".tools/dependency-audit-latest.json"
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(result, indent=2) + "\n")
    for name, graph in graphs.items():
        external = sum(package["source"] == REGISTRY for package in graph["packages"])
        print(f"{name}: {external} external packages; no RustSec findings or warnings.")
    print(f"Database: {revision}; result: {destination.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
