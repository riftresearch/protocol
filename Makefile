# n-prefix commands utilize nextest, which provides better devex over cargo test:
# See: https://nexte.st/docs/installation/pre-built-binaries/
sync:
	cd contracts && ./sync-artifacts.sh

build: 
	cargo build --release

test-contracts: 
	cargo build --release --bin sol-utils 
	cd contracts && forge test

test-crates: | build
	cargo test --release --workspace --exclude rift-program

ntest-circuits:
	cargo nextest run --release -p rift-core -p bitcoin-light-client-core -p bitcoin-core-rs

test: | build test-contracts test-crates
	@echo "All tests passed"

ntest-crates: | build
	cargo nextest run --release --workspace --exclude rift-program --exclude test_market_maker_hypernode_end_to_end

ntest: | build test-contracts ntest-crates
	@echo "All tests passed"
