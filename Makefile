sync:
	cd contracts && forge build  && ./sync-artifacts.sh

build: | sync
	cargo build --release

test-contracts: | sync 
	cargo build --release --bin test-utils 
	cd contracts  && forge test

test-crates: | build
	cargo test --release --workspace --exclude rift-program

test: | build test-contracts test-crates
