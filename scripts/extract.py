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
                        "--start-from", "pathward::is_public",
                        "--start-from", "pathward::rules::compile",
                        "--start-from", "pathward::rules::lookup",
                        "--start-from", "pathward::serving::authorize",
                        "--start-from", "pathward::serving::file_allowed",
                        "--start-from", "pathward::tls::identity_allowed",
                        "--start-from", "pathward::tls::secret_allowed",
                        "--start-from", "pathward::tls::activate",
                        "--start-from", "pathward::tls::renewal_due",
                        "--start-from", "pathward::runtime::commit_generation",
                        "--start-from", "pathward::runtime::ready",
                        "--start-from", "pathward::response::header_allowed",
                        "--start-from", "pathward::response::redirect_allowed",
                        "--start-from", "pathward::response::route_matches",
                        "--start-from", "pathward::response::authority_port",
                        "--start-from", "pathward::response::authority_port_allowed",
                        "--start-from", "pathward::response::forwarded_port",
                        "--start-from", "pathward::release::generated_rule",
                        "--start-from", "pathward::release::commit_allowed",
                        "--start-from", "pathward::release::admission_allowed",
                        "--start-from", "pathward::release::admission_rejection",
                        "--start-from", "pathward::release::dispatch_allowed",
                        "--start-from", "pathward::release::capacity_global",
                        "--start-from", "pathward::release::capacity_peer",
                        "--start-from", "pathward::release::capacity_queue",
                        "--start-from", "pathward::release::capacity_rate",
                        "--start-from", "pathward::release::capacity_burst",
                        "--start-from", "pathward::release::capacity_rejection",
                        "--start-from", "pathward::release::capacity_reload_allowed",
                        "--start-from", "pathward::release::migration_allowed",
                        "--start-from", "pathward::proxy::site_mode_allowed",
                        "--start-from", "pathward::proxy::endpoint_allowed",
                        "--start-from", "pathward::proxy::method_allowed",
                        "--start-from", "pathward::proxy::status_allowed",
                        "--start-from", "pathward::proxy::request_framing",
                        "--start-from", "pathward::proxy::response_framing",
                        "--start-from", "pathward::proxy::target_allowed",
                        "--start-from", "pathward::proxy::request_header",
                        "--start-from", "pathward::proxy::response_header",
                        "--start-from", "pathward::routing::select",
                        "--start-from", "pathward::routing::stem",
                        "--start-from", "pathward::routing::subtree",
                        "--start-from", "pathward::routing::body_limit",
                        "--start-from", "pathward::routing::body_fits",
                        "--start-from", "pathward::routing::chunk_fits",
                        "--start-from", "pathward::routing::time_limits",
                        "--start-from", "pathward::routing::connection_limit",
                        "--start-from", "pathward::routing::service_admit",
                        "--start-from", "pathward::routing::request_framing",
                        "--start-from", "pathward::routing::response_framing",
                        "--start-from", "pathward::streaming::upgrade_request",
                        "--start-from", "pathward::streaming::upgrade_response",
                        "--start-from", "pathward::streaming::sse_response",
                        "--start-from", "pathward::streaming::byte_limit",
                        "--start-from", "pathward::streaming::bytes_fit",
                        "--start-from", "pathward::streaming::time_limits",
                        "--start-from", "pathward::streaming::running",
                        "--start-from", "pathward::streaming::admission",
                        "--start-from", "pathward::streaming::peer_admission",
                        "--start-from", "pathward::streaming::service_limit",
                        "--start-from", "pathward::streaming::service_admission",
                        "--start-from", "pathward::streaming::origin_allowed",
                        "--start-from", "pathward::streaming::deflate_allowed",
                        "--start-from", "pathward::content::span_allowed",
                        "--start-from", "pathward::content::precondition_status",
                        "--start-from", "pathward::content::shared_cache_allowed",
                        "--start-from", "pathward::upstream::probe_allowed",
                        "--start-from", "pathward::upstream::probe_next",
                        "--start-from", "pathward::upstream::probe_owned",
                        "--start-from", "pathward::upstream::query_match",
                        "--dest-file", str(llbc)],
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
