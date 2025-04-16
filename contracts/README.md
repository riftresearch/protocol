# Rift Exchange Contracts

## Dependencies

- [Foundry](https://github.com/foundry-rs/foundry)

### Installation

To install contract dependencies, run the following command:

```bash
forge soldeer install
```

## Deployments

### Arbitrum Mainnet

#### Deploy Rift Exchange
```bash
source .env && forge clean && forge build --via-ir && \
forge script --chain arbitrum scripts/DeployRiftExchange.s.sol:DeployRiftExchange \
--rpc-url $ARBITRUM_RPC_URL --broadcast --sender $SENDER --private-key $SENDER_PRIVATE_KEY \
--verify --etherscan-api-key $ARBITRUM_ETHERSCAN_API_KEY --ffi -vvvv --via-ir
```

### Development Workflow  
*Execute all commands from the project root.*

- **When contract code changes (unneccessary if only tests are updated):**  
  ```bash
  make sync
  ```

- **To build the FFI helper and then run the full contract test suite:**  
  ```bash
  make test-contracts
  ```

### Unit Tests
```bash
forge test
```

### Static Analysis

#### Slither
1. Install [slither](https://github.com/crytic/slither)
2. Run:
   ```bash
   python -m slither .
   ```

#### Mythril
1. Install [mythril](https://github.com/ConsenSys/mythril)
2. Run:
   ```bash
   myth analyze src/RiftExchange.sol --solc-json mythril.config.json
   ```
