sync:
	cd contracts && forge build && ./sync-artifacts.sh

build: 
	cargo build --release

test-contracts: 
	cargo build --release --bin sol-utils 
	cd contracts && forge test

test-crates: | build
	cargo test --release --workspace --exclude rift-program


test: | build test-contracts test-crates
	@echo "All tests passed"

# nextest provides better UX over cargo test:
# See: https://nexte.st/docs/installation/pre-built-binaries/
ntest-crates: | build
	cargo nextest run --release --workspace --exclude rift-program

ntest: | build test-contracts ntest-crates
	@echo "All tests passed"
