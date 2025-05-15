# E2E Tests 

## Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) 
- [Docker](https://docs.docker.com/get-docker/) 
- [Foundry](https://getfoundry.sh) 


## Running the Devnet
The devnet provides a local development environment with both Bitcoin and Ethereum networks. To run it:

```bash
# Basic run with default settings
cargo run --release --bin devnet

# Run with a funded EVM address (receives initial ETH and tokens)
cargo run --release --bin devnet -- --addresses 0x82bdA835Ab91D3F38Cb291030A5B0e6Dff086d44

# Run with forking from a specific network
cargo run --release --bin devnet -- --fork-url <RPC_URL> --fork-block-number <BLOCK_NUMBER>
```

The devnet will start:
- A local Bitcoin regtest network
- An Ethereum network (Anvil)
- All deployed contracts
- A data engine server for querying onchain order state 