# Rift Devnet CLI

The Rift devnet CLI provides a local development environment for testing the Rift protocol.

## Usage

The devnet CLI has two commands:

### Server Command 

Run an interactive devnet server (the default mode):

```bash
cargo run --release --bin devnet server --fork-url <RPC_URL> [OPTIONS]
```

Options:
- `-f, --fork-url <URL>`: RPC URL to fork from (required)
- `-b, --fork-block-number <NUMBER>`: Block number to fork from (optional, uses latest if not specified)
- `--fund-address <ADDRESS>`: Address to fund with cbBTC and Ether (can be specified multiple times)

Example:
```bash
cargo run --release --bin devnet server \
  --fork-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  --fund-address 0x1234567890123456789012345678901234567890
```

### Cache Mode

Create a cached devnet for improving the time to boot devnets during integration tests:

```bash
cargo run --release --bin devnet cache
```

This will:
1. Clear your any existing cache
2. Build a fresh devnet then save all state to `~/.cache/rift-devnet/`
3. Exit after successful caching

The cached devnet significantly speeds up subsequent devnet launches by avoiding:
- Re-mining Bitcoin blocks
- Re-deploying contracts
- Re-indexing blockchain data

## Docker

The devnet-cli server is also available as a Docker image:

```bash
docker run -it -p 50101:50101 -p 50100:50100 riftresearch/devnet:latest server --fork-url <RPC_URL>
```