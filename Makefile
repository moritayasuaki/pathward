.PHONY: setup extract check rust-check proof-check audit

# Network/toolchain installation is explicit; ordinary checks install nothing.
setup:
	python3 scripts/setup.py

extract:
	python3 scripts/extract.py

rust-check:
	cargo fmt --check
	cargo test --offline --locked
	cargo clippy --offline --locked --all-targets -- -D warnings

proof-check:
	python3 scripts/extract.py --check
	cd proofs && lake build
	python3 scripts/audit.py

check: rust-check proof-check

.PHONY: dependency-audit-setup dependency-audit dependency-check

dependency-audit-setup:
	cargo install cargo-audit --version 0.22.2 --locked --no-default-features --root .tools/audit

dependency-audit:
	python3 scripts/dependency_audit.py

dependency-check:
	cargo check --locked --manifest-path audit/server-stack/Cargo.toml
