# n-prefix commands utilize nextest, which provides better devex over cargo test:
# See: https://nexte.st/docs/installation/pre-built-binaries/
sync:
	cd contracts && ./sync-artifacts.sh
	$(MAKE) cache-devnet
	@echo "Sync and cache-devnet complete"

build: 
	cargo build --release
	@echo "Build complete"

test-contracts: 
	cargo build --release --bin sol-utils 
	cd contracts && forge test
	@echo "Test contracts complete"

cache-devnet: | build
	cargo run --release --bin devnet -- cache
	@echo "Devnet cached"

ntest-circuits:
	cargo nextest run --release -p rift-core -p bitcoin-light-client-core -p bitcoin-core-rs
	@echo "Test circuits complete"

ntest-crates: | cache-devnet 
	cargo nextest run --release --workspace --exclude rift-program -- --skip market_maker_hypernode_end_to_end --skip test_dual_hypernode_market_maker_order_filling
	@echo "Test crates complete"

ntest: | cache-devnet test-contracts ntest-crates
	@echo "All tests passed"
