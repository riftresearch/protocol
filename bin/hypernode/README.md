# Hypernode

Hypernode maintains synchronized internal states between the Rift Exchange contract (Ethereum) and the Bitcoin blockchain to facilitate the generation of cryptographic proofs of payment.

## Overview
Hypernode operates through several concurrent modules:

- **Contract Data Engine (CDE)**:
  - Monitors Ethereum events, maintaining a SQLite database of deposits, swaps, and the Bitcoin light client state (using an MMR structure).

- **Bitcoin Data Engine (BDE)**:
  - Maintains a real-time local MMR representation of the Bitcoin blockchain, handling reorganizations.

- **Transaction Broadcaster**:
  - Manages nonce correctness and broadcasts transactions, with contract-revert error handling.

- **Swap Watchtower**:
  - Identifies Bitcoin transactions associated with Rift swaps, validates confirmations, and generates cryptographic proofs.

- **Release Watchtower**:
  - Automates the release of liquidity that has successfully gone through it's challenge period.

- **Fork Watchtower**:
  - Detects Bitcoin blockchain reorganizations and updates the on-chain light client accordingly.


## Configuration
Provide environment variables either via `.env` file or directly in the environment:

```env
EVM_WS_RPC="your_ethereum_websocket_rpc_url"
BTC_RPC="your_bitcoin_rpc_url"
PRIVATE_KEY="your_ethereum_private_key"
CHECKPOINT_FILE="path_to_bitcoin_checkpoint_file"
DATABASE_LOCATION="memory or /path/to/db"
RIFT_EXCHANGE_ADDRESS="rift_exchange_contract_address"
DEPLOY_BLOCK_NUMBER="block_number_of_rift_contract_deployment"
```

## Running the Hypernode

Execute the binary with:

```bash
RUST_LOG=info cargo run --release --bin hypernode
```


## Tests
There are scattered unit tests all throughout the codebase.
Integration tests that interact with an automated devnet are here:
- [End to End Hypernode Tests](../../integration-tests/src/hypernode_test.rs)
- [Transaction Broadcaster Tests](../../integration-tests/src/txn_broadcast_test.rs)