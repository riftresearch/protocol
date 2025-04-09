# Rift Protocol Monorepo  
Trustless cross-chain swap protocol for Bitcoin and Ethereum

#### Highlights:
- [`bitcoin-light-client-core`](./crates/bitcoin-light-client-core/): Circuit validating Bitcoin consensus within an MMR-based light client.
- [`rift-core`](./crates/rift-core/): Circuit handling Bitcoin<>Ethereum order settlement and light client state updates.
- [`contracts`](./contracts): Solidity smart contracts for settling orders, and maintaining the light client state.
- [`hypernode`](./bin/hypernode): Bitcoin and Ethereum indexer that generates swap proofs, settles challenged proofs, and detects and removes orphan blocks submitted to the light client.

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

