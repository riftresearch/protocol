# Rift Protocol Monorepo
All the components that secure Rift
- [`bitcoin-light-client-program`](./crates/bitcoin-light-client-program/): Circuit validating Bitcoin Proof of Work and longest chain
- [`rift-settlement-program`](./crates/rift-settlement-program/): Circuit validating Bitcoin<>Ethereum order settlement
- [`contracts`](./contracts): Solidity smart contracts for the Rift Settlement Layer 
- [`hypernode`](./bin/hypernode): Bitcoin and Ethereum indexer with hooks to trigger proof generation
- [`e2e-tests`](./bin/hypernode): End-to-end testing suite for the entire system 
- [`data-aggregation-contracts`](./data-aggregation-contracts): Contracts for aggregating and processing on-chain data in client code

## Dependencies

### Ubuntu
To install the required dependencies on Ubuntu, run:
```sh
sudo apt update
sudo apt install -y clang pkg-config libssl-dev build-essential
```

### macOS
For macOS, you can install the dependencies using Homebrew:
```sh
brew install pkg-config openssl
```

## Prerequisites
Ensure you have the following tools installed:

- [Rust](https://doc.rust-lang.org/cargo/getting-started/installation.html)
- [SP1](https://docs.succinct.xyz/docs/sp1/getting-started/install)
- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- [Git LFS](https://git-lfs.github.com/)

  
## Run Devnet
```sh
cargo run --release --bin devnet
```
Alternatively, the devnet is packaged as a docker image: 
```sh
docker run -it -p 50101:50101 -p 50100:50100 riftresearch/devnet:latest
```

