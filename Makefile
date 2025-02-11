sync:
	cd contracts && forge soldeer install && forge build  && ./sync-artifacts.sh

build: | sync
	cargo build --release

test-contracts: | sync 
	cargo build --release --bin test-utils 
	cd contracts && forge test

test-crates: | build
	cargo test --release --workspace --exclude rift-program

test: | build test-contracts test-crates
	@echo "All tests passed"