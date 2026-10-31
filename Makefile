.PHONY: setup extract check rust-check proof-check audit

# Network/toolchain installation is explicit; ordinary checks install nothing.
setup:
	python3 scripts/setup.py
	$(MAKE) config-setup
	$(MAKE) server-setup

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

check: rust-check config-check server-check proof-check

.PHONY: config-setup config-check

config-setup:
	cargo fetch --locked --manifest-path config/Cargo.toml

config-check:
	cargo fmt --manifest-path config/Cargo.toml --check
	cargo test --offline --locked --manifest-path config/Cargo.toml
	cargo clippy --offline --locked --manifest-path config/Cargo.toml --all-targets -- -D warnings

.PHONY: dependency-audit-setup dependency-audit dependency-check

dependency-audit-setup:
	cargo install cargo-audit --version 0.22.2 --locked --no-default-features --root .tools/audit

dependency-audit:
	python3 scripts/dependency_audit.py

dependency-check:
	cargo check --locked --manifest-path audit/server-stack/Cargo.toml

.PHONY: server-setup server-check server-build

server-setup:
	rustup toolchain install 1.99.1 --profile minimal --component rustfmt --component clippy
	cargo +1.99.1 fetch --locked --manifest-path server/Cargo.toml

server-check:
	cargo +1.99.1 fmt --manifest-path server/Cargo.toml --check
	cargo +1.99.1 test --offline --locked --manifest-path server/Cargo.toml
	cargo +1.99.1 clippy --offline --locked --manifest-path server/Cargo.toml --all-targets -- -D warnings

server-build:
	cargo +1.99.1 build --offline --locked --release --manifest-path server/Cargo.toml

.PHONY: acme-test-setup acme-integration
acme-test-setup:
	python3 scripts/acme_test_setup.py

acme-integration:
	python3 scripts/acme_integration.py
