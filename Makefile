.PHONY: build test fmt fmt-fix clippy lint docs docs-nightly check-no-std eth-tests ci help

.DEFAULT_GOAL := help

build: ## Compile the workspace
	cargo build --workspace

test: ## Run tests (default features)
	cargo test --workspace

fmt: ## Check formatting
	cargo fmt --all --check

fmt-fix: ## Apply formatting
	cargo fmt --all

clippy: ## Run Clippy with all features, deny warnings
	RUSTFLAGS="-Dwarnings" cargo clippy --workspace --all-targets --all-features

lint: fmt clippy ## Check formatting + Clippy

docs: ## Build docs (stable, ci.yml docs job)
	RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo doc --workspace --all-features --no-deps --document-private-items

docs-nightly: ## Build docs with index page (nightly, book.yml build job)
	RUSTDOCFLAGS="--enable-index-page -Zunstable-options" cargo +nightly doc --all --no-deps

check-no-std: ## Check no_std on riscv32/riscv64 (requires targets via rustup)
	cargo check --target riscv32imac-unknown-none-elf --no-default-features
	cargo check --target riscv32imac-unknown-none-elf -p op-revm --no-default-features
	cargo check --target riscv32imac-unknown-none-elf -p revm-database --no-default-features
	cargo check --target riscv64imac-unknown-none-elf --no-default-features
	cargo check --target riscv64imac-unknown-none-elf -p op-revm --no-default-features
	cargo check --target riscv64imac-unknown-none-elf -p revm-database --no-default-features

eth-tests: ## Run Ethereum state/blockchain tests (downloads fixtures if needed)
	./scripts/run-tests.sh

ci: lint docs test check-no-std ## Run the full local CI suite

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
