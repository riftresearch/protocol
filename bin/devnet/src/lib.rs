//! `lib.rs` — central library code.

pub mod bitcoin_devnet;
pub mod evm_devnet;

use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use bitcoin_data_engine::BitcoinDataEngine;
pub use bitcoin_devnet::BitcoinDevnet;
pub use evm_devnet::EthDevnet;

use evm_devnet::{EvmWebsocketProvider, ForkConfig};
use eyre::Result;
use log::info;
use rift_sdk::bindings::RiftExchange;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use data_engine::engine::DataEngine;
use data_engine_server::DataEngineServer;

use rift_sdk::{get_rift_program_hash, DatabaseLocation};

use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::RpcApi;
use rift_sdk::bitcoin_utils::{AsyncBitcoinClient, BitcoinClientExt};

// ================== Contract ABIs ================== //

const TOKEN_ADDRESS: &str = "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf";
const TOKEN_SYMBOL: &str = "cbBTC";
const TOKEN_NAME: &str = "Coinbase Wrapped BTC";
const TOKEN_DECIMALS: u8 = 8;
const CONTRACT_DATA_ENGINE_SERVER_PORT: u16 = 50100;

use alloy::sol;

/// The mock token artifact
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    MockToken,
    "../../contracts/artifacts/MockToken.json"
);

/// The SP1 mock verifier
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SP1MockVerifier,
    "../../contracts/artifacts/SP1MockVerifier.json"
);

use alloy::network::{Ethereum, EthereumWallet, NetworkWallet};
use alloy::primitives::{Address as EvmAddress, U256};
use alloy::providers::{Identity, Provider, RootProvider};
use alloy::pubsub::PubSubConnect;
use alloy::pubsub::PubSubFrontend;

pub type RiftExchangeWebsocket =
    RiftExchange::RiftExchangeInstance<PubSubFrontend, EvmWebsocketProvider>;

pub type MockTokenWebsocket = MockToken::MockTokenInstance<PubSubFrontend, EvmWebsocketProvider>;

// ================== Deploy Function ================== //

use alloy::{node_bindings::AnvilInstance, signers::Signer};

/// Deploy all relevant contracts: RiftExchange & MockToken
/// Return `(RiftExchange, MockToken, deployment_block_number)`.
pub async fn deploy_contracts(
    anvil: &AnvilInstance,
    circuit_verification_key_hash: [u8; 32],
    genesis_mmr_root: [u8; 32],
    tip_block_leaf: BlockLeaf,
    on_fork: bool,
) -> Result<(Arc<RiftExchangeWebsocket>, Arc<MockTokenWebsocket>, u64)> {
    use alloy::{
        hex::FromHex,
        primitives::Address,
        providers::{ext::AnvilApi, ProviderBuilder, WsConnect},
        signers::local::PrivateKeySigner,
    };
    use eyre::eyre;
    use std::str::FromStr;

    let deployer_signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let deployer_wallet = EthereumWallet::from(deployer_signer.clone());
    let deployer_address = deployer_wallet.default_signer().address();

    // Build a provider
    let provider = Arc::new(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(deployer_wallet)
            .on_ws(WsConnect::new(anvil.ws_endpoint_url()))
            .await
            .map_err(|e| eyre!("Error connecting to Anvil: {e}"))?,
    );

    let verifier_contract = Address::from_str("0xaeE21CeadF7A03b3034DAE4f190bFE5F861b6ebf")?;
    // Insert the SP1MockVerifier bytecode
    provider
        .anvil_set_code(verifier_contract, SP1MockVerifier::BYTECODE.clone())
        .await?;

    let token_address = EvmAddress::from_str(TOKEN_ADDRESS)?;
    // Deploy the mock token, this is dependent on if we're on a fork or not
    let token = if !on_fork {
        // deploy it
        let mock_token = MockToken::deploy(
            provider.clone(),
            TOKEN_NAME.to_string(),
            TOKEN_SYMBOL.to_string(),
            TOKEN_DECIMALS,
        )
        .await?;
        provider
            .anvil_set_code(
                token_address,
                provider.get_code_at(*mock_token.address()).await?,
            )
            .await?;
        MockToken::new(token_address, provider.clone())
    } else {
        MockToken::new(token_address, provider.clone())
    };

    // Record the block number to track from
    let deployment_block_number = provider.get_block_number().await?;

    let tip_block_leaf_sol: sol_types::Types::BlockLeaf = tip_block_leaf.into();
    // Deploy RiftExchange
    let exchange = RiftExchange::deploy(
        provider.clone(),
        genesis_mmr_root.into(),
        *token.address(),
        circuit_verification_key_hash.into(),
        verifier_contract,
        deployer_address, // e.g. owner
        // TODO: any way to not do this goofy conversion? need to deduplicate the types
        rift_sdk::bindings::Types::BlockLeaf {
            blockHash: tip_block_leaf_sol.blockHash,
            height: tip_block_leaf_sol.height,
            cumulativeChainwork: tip_block_leaf_sol.cumulativeChainwork,
        },
    )
    .await?;

    Ok((Arc::new(exchange), Arc::new(token), deployment_block_number))
}

// ================== RiftDevnet ================== //

/// The "combined" Devnet which holds:
/// - a `BitcoinDevnet`
/// - an `EthDevnet`
/// - a `DataEngine` (for your chain indexing)
/// - an optional `DataEngineServer`
pub struct RiftDevnet {
    pub bitcoin: BitcoinDevnet,
    pub ethereum: EthDevnet,
    pub contract_data_engine: Arc<DataEngine>,
    pub _data_engine_server: Option<DataEngineServer>,
}

impl RiftDevnet {
    /// The main entry point to set up a devnet with both sides plus data engine.
    /// Returns `(RiftDevnet, funding_sats)`.
    pub async fn setup(
        interactive: bool,
        funded_evm_address: Option<String>,
        funded_bitcoin_address: Option<String>,
        fork_config: Option<ForkConfig>,
    ) -> Result<(Self, u64)> {
        println!("Setting up RiftDevnet...");
        // 1) Bitcoin side
        let bitcoin_devnet = BitcoinDevnet::setup(funded_bitcoin_address)?;
        let funding_sats = bitcoin_devnet.funded_sats;

        // 2) Grab some additional info (like checkpoint leaves)
        info!("Downloading checkpoint leaves from block range 0..101");
        let checkpoint_leaves = bitcoin_devnet
            .rpc_client
            .get_leaves_from_block_range(0, 101, None, None)
            .await?;

        let tip_block_leaf = &checkpoint_leaves.last().unwrap().clone();

        // 4) Data Engine
        info!("Seeding data engine with checkpoint leaves...");
        let t = Instant::now();
        let mut contract_data_engine =
            DataEngine::seed(&DatabaseLocation::InMemory, checkpoint_leaves).await?;
        info!("Data engine seeded in {:?}", t.elapsed());

        // 3) Start EVM side
        let circuit_verification_key_hash = get_rift_program_hash();
        let (ethereum_devnet, deployment_block_number) = EthDevnet::setup(
            circuit_verification_key_hash,
            contract_data_engine.get_mmr_root().await.unwrap(),
            *tip_block_leaf,
            fork_config,
        )
        .await?;

        // Start listening for on-chain events from RiftExchange
        contract_data_engine
            .start_event_listener(
                ethereum_devnet.funded_provider.clone(),
                ethereum_devnet.rift_exchange_contract.address().to_string(),
                deployment_block_number,
            )
            .await?;

        let contract_data_engine = Arc::new(contract_data_engine);

        // Possibly run a local data-engine HTTP server
        let contract_data_engine_server = if interactive {
            let server = DataEngineServer::from_engine(
                contract_data_engine.clone(),
                CONTRACT_DATA_ENGINE_SERVER_PORT,
            )
            .await?;
            Some(server)
        } else {
            None
        };

        if interactive {
            println!("---RIFT DEVNET---");
            println!(
                "Anvil HTTP Url:        http://0.0.0.0:{}",
                ethereum_devnet.anvil.port()
            );
            println!(
                "Anvil WS Url:          ws://0.0.0.0:{}",
                ethereum_devnet.anvil.port()
            );
            println!(
                "Anvil Chain ID:        {}",
                ethereum_devnet.anvil.chain_id()
            );
            println!(
                "Data Engine HTTP URL:  http://0.0.0.0:{}",
                CONTRACT_DATA_ENGINE_SERVER_PORT
            );
            println!(
                "Bitcoin RPC URL:       {}",
                bitcoin_devnet.regtest.rpc_url()
            );
            println!(
                "{} Address:  {}",
                TOKEN_SYMBOL,
                ethereum_devnet.token_contract.address()
            );
            println!(
                "{} Address:  {}",
                "Rift Exchange",
                ethereum_devnet.rift_exchange_contract.address()
            );
            println!("---RIFT DEVNET---");
        }

        // If we want to fund an EVM address
        if let Some(addr_str) = funded_evm_address {
            use alloy::primitives::Address;
            use std::str::FromStr;

            let address = Address::from_str(&addr_str)?;
            // Fund with ~100 ETH
            ethereum_devnet
                .fund_eth_address(address, U256::from_str("10000000000000000000")?)
                .await?;

            // Fund with e.g. 1_000_000 tokens
            ethereum_devnet
                .mint_token(address, U256::from_str("10000000000000000000")?)
                .await?;

            // get the balance of the funded address
            let balance = ethereum_devnet.funded_provider.get_balance(address).await?;
            println!("Ether Balance: {:?}", balance);
            let token_balance = ethereum_devnet
                .token_contract
                .balanceOf(address)
                .call()
                .await?
                ._0;
            println!("Token Balance: {:?}", token_balance);
        }

        // Build final devnet
        let devnet = Self {
            bitcoin: bitcoin_devnet,
            ethereum: ethereum_devnet,
            contract_data_engine,
            _data_engine_server: contract_data_engine_server,
        };

        Ok((devnet, funding_sats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RiftDevnet;
    use ::bitcoin::consensus::{Decodable, Encodable};
    use ::bitcoin::hashes::serde::Serialize;
    use ::bitcoin::hashes::Hash;
    use ::bitcoin::{Amount, Transaction};
    use accumulators::mmr::map_leaf_index_to_element_index;
    use alloy::eips::eip6110::DEPOSIT_REQUEST_TYPE;
    use alloy::hex;
    use alloy::primitives::utils::{format_ether, format_units};
    use alloy::primitives::{Address as EvmAddress, U256};
    use alloy::providers::ext::AnvilApi;
    use alloy::providers::{ProviderBuilder, WalletProvider, WsConnect};
    use alloy::signers::local::LocalSigner;
    use alloy::sol_types::{SolEvent, SolValue};
    use bitcoin::hashes::serde::Deserialize;
    use bitcoin_light_client_core::hasher::Keccak256Hasher;
    use bitcoin_light_client_core::leaves::BlockLeaf as CoreBlockLeaf;
    use bitcoin_light_client_core::light_client::Header;
    use bitcoin_light_client_core::mmr::MMRProof as CircuitMMRProof;
    use bitcoin_light_client_core::{BlockPosition, ChainTransition};
    use bitcoincore_rpc_async::bitcoin::hashes::Hash as BitcoinHash;
    use bitcoincore_rpc_async::bitcoin::util::psbt::serialize::Serialize as AsyncSerialize;
    use bitcoincore_rpc_async::bitcoin::BlockHash;
    use rift_core::giga::RiftProgramInput;
    use rift_core::spv::generate_bitcoin_txn_merkle_proof;
    use rift_core::vaults::hash_deposit_vault;
    use rift_core::RiftTransaction;
    use rift_sdk::bindings::non_artifacted_types::Types::MMRProof;
    use rift_sdk::bindings::non_artifacted_types::Types::{BlockLeaf, ProofPublicInput};
    use rift_sdk::bindings::Types::BlockProofParams;
    use rift_sdk::mmr::client_mmr_proof_to_circuit_mmr_proof;
    use rift_sdk::txn_builder::{self, serialize_no_segwit, P2WPKHBitcoinWallet};
    use rift_sdk::{
        create_websocket_provider, get_retarget_height_from_block_height, DatabaseLocation,
        ProofGeneratorType, RiftProofGenerator,
    };
    use tokio::signal;

    /// Test the end-to-end swap flow, fully simulated:
    ///  1) Create bitcoin and EVM devnets
    ///  2) Deploy the RiftExchange + MockToken (done in `RiftDevnet::setup`)
    ///  3) Maker deposits liquidity (ERC20 -> RiftExchange)
    ///  4) Taker broadcasts a (mocked) Bitcoin transaction paying maker's scriptPubKey + OP_RETURN
    ///  5) Generate a "swap proof" referencing that Bitcoin transaction
    ///  6) Submit the swap proof to finalize the swap on the RiftExchange
    ///  7) Check final on-chain state
    #[tokio::test]
    async fn test_simulated_swap_end_to_end() {
        // ---1) Spin up devnet with default config---
        //    Interactive = false => no local HTTP servers / Docker containers
        //    No pre-funded EVM or Bitcoin address => we can do that ourselves below

        let maker_secret_bytes: [u8; 32] = [0x01; 32];
        let taker_secret_bytes: [u8; 32] = [0x02; 32];

        let maker_evm_wallet =
            EthereumWallet::new(LocalSigner::from_bytes(&maker_secret_bytes.into()).unwrap());

        let taker_evm_wallet =
            EthereumWallet::new(LocalSigner::from_bytes(&taker_secret_bytes.into()).unwrap());

        let maker_evm_address = maker_evm_wallet.default_signer().address();

        let taker_evm_address = taker_evm_wallet.default_signer().address();

        let maker_btc_wallet = P2WPKHBitcoinWallet::from_secret_bytes(
            &maker_secret_bytes,
            ::bitcoin::Network::Regtest,
        );

        let taker_btc_wallet = P2WPKHBitcoinWallet::from_secret_bytes(
            &taker_secret_bytes,
            ::bitcoin::Network::Regtest,
        );

        println!(
            "Maker BTC P2WPKH: {:?}",
            maker_btc_wallet.get_p2wpkh_script().to_hex_string()
        );
        println!(
            "Taker BTC P2WPKH: {:?}",
            taker_btc_wallet.get_p2wpkh_script().to_hex_string()
        );
        println!("Maker BTC wallet: {:?}", maker_btc_wallet.address);
        println!("Taker BTC wallet: {:?}", taker_btc_wallet.address);
        println!("Maker EVM wallet: {:?}", maker_evm_address);
        println!("Taker EVM wallet: {:?}", taker_evm_address);

        // create the proof generator
        let proof_generator_handle =
            tokio::task::spawn_blocking(|| RiftProofGenerator::new(ProofGeneratorType::Execute));

        // fund maker evm wallet, and taker btc wallet
        let (devnet, _funded_sats) = RiftDevnet::setup(
            /*interactive=*/ false,
            /*funded_evm_address=*/ Some(maker_evm_address.to_string()),
            /*funded_bitcoin_address=*/ None,
            /*fork_config=*/ None,
        )
        .await
        .expect("Failed to set up devnet");

        let maker_evm_provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(maker_evm_wallet)
            .on_ws(WsConnect::new(devnet.ethereum.anvil.ws_endpoint_url()))
            .await
            .expect("Failed to create maker evm provider");

        // Quick references
        let rift_exchange = devnet.ethereum.rift_exchange_contract.clone();
        let token_contract = devnet.ethereum.token_contract.clone();

        // ---2) "Maker" address gets some ERC20 to deposit---

        println!("Maker address: {:?}", maker_evm_address);

        let deposit_amount = U256::from(100_000_000u128); //1 wrapped bitcoin
        let expected_sats = 100_000_000u64; // The maker wants 1 bitcoin for their 1 million tokens (1 BTC = 1 cbBTC token)

        let decimals = devnet
            .ethereum
            .token_contract
            .decimals()
            .call()
            .await
            .unwrap()
            ._0;

        println!(
            "Approving {} tokens to maker",
            format_units(deposit_amount, decimals).unwrap()
        );

        // Approve the RiftExchange to spend the maker's tokens
        let approve_call = token_contract.approve(*rift_exchange.address(), deposit_amount);
        maker_evm_provider
            .send_transaction(approve_call.into_transaction_request())
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();

        println!("Approved");

        // ---3) Maker deposits liquidity into RiftExchange---
        // We'll fill in some "fake" deposit parameters.
        // This is just an example; in real usage you'd call e.g. depositLiquidity(...) with your chosen params.

        use rift_sdk::bindings::Types::BlockLeaf as ContractBlockLeaf;
        use rift_sdk::bindings::Types::DepositLiquidityParams;

        // We can skip real MMR proofs; for dev/test, we can pass dummy MMR proof data or a known "safe block."
        // For example, we'll craft a dummy "BlockLeaf" that the contract won't reject:
        let (safe_leaf, safe_siblings, safe_peaks) =
            devnet.contract_data_engine.get_tip_proof().await.unwrap();

        let mmr_root = devnet.contract_data_engine.get_mmr_root().await.unwrap();

        let safe_leaf: sol_types::Types::BlockLeaf = safe_leaf.into();

        println!("Safe leaf tip (data engine): {:?}", safe_leaf);
        println!("Mmr root (data engine): {:?}", hex::encode(mmr_root));

        let light_client_height = devnet
            .ethereum
            .rift_exchange_contract
            .getLightClientHeight()
            .call()
            .await
            .unwrap()
            ._0;

        let mmr_root = devnet
            .ethereum
            .rift_exchange_contract
            .mmrRoot()
            .call()
            .await
            .unwrap()
            ._0;
        println!("Light client height (queried): {:?}", light_client_height);
        println!("Mmr root (queried): {:?}", mmr_root);

        let deposit_params = DepositLiquidityParams {
            depositOwnerAddress: maker_evm_address,
            specifiedPayoutAddress: taker_evm_address,
            depositAmount: deposit_amount,
            expectedSats: expected_sats,
            btcPayoutScriptPubKey: maker_btc_wallet
                .get_p2wpkh_script()
                .as_bytes()
                .try_into()
                .unwrap(),
            depositSalt: [0x44; 32].into(), // this can be anything
            confirmationBlocks: 2, // require 2 confirmations (1 block to mine + 1 additional)
            // TODO: This is hellacious, remove the 3 different types for BlockLeaf somehow
            safeBlockLeaf: ContractBlockLeaf {
                blockHash: safe_leaf.blockHash,
                height: safe_leaf.height,
                cumulativeChainwork: safe_leaf.cumulativeChainwork,
            },
            safeBlockSiblings: safe_siblings.iter().map(From::from).collect(),
            safeBlockPeaks: safe_peaks.iter().map(From::from).collect(),
        };
        println!("Deposit params: {:?}", deposit_params);

        let deposit_call = rift_exchange.depositLiquidity(deposit_params);

        let deposit_calldata = deposit_call.calldata();

        let deposit_tx = maker_evm_provider
            .send_transaction(deposit_call.clone().into_transaction_request())
            .await;

        let receipt = match deposit_tx {
            Ok(tx) => {
                let receipt = tx.get_receipt().await.expect("No deposit tx receipt");
                println!("Deposit receipt: {:?}", receipt);
                receipt
            }
            Err(tx_error) => {
                println!("Deposit error: {:?}", tx_error);
                let block_height = devnet
                    .ethereum
                    .funded_provider
                    .get_block_number()
                    .await
                    .map_err(|e| eyre::eyre!(e))
                    .unwrap();

                let data = hex::encode(deposit_calldata);
                let from = maker_evm_address.to_string();
                let to = rift_exchange.address().to_string();
                println!(
                    "To debug failed proof broadcast run: cast call {} --from {} --data {} --trace --block {} --rpc-url {}",
                    to,
                    from,
                    data,
                    block_height,
                    devnet.ethereum.anvil.endpoint()
                );
                // contorl c pause here
                signal::ctrl_c().await.unwrap();
                panic!("Deposit failed");
            }
        };

        let receipt_logs = receipt.inner.logs();
        // this will have only a VaultsUpdated log
        let vaults_updated_log = RiftExchange::VaultsUpdated::decode_log(
            &receipt_logs
                .iter()
                .find(|log| *log.topic0().unwrap() == RiftExchange::VaultsUpdated::SIGNATURE_HASH)
                .unwrap()
                .inner,
            false,
        )
        .unwrap();

        let new_vault = &vaults_updated_log.data.vaults[0];
        let vault_commitment = hash_deposit_vault(&sol_types::Types::DepositVault {
            vaultIndex: new_vault.vaultIndex,
            depositTimestamp: new_vault.depositTimestamp,
            depositAmount: new_vault.depositAmount,
            depositFee: new_vault.depositFee,
            expectedSats: new_vault.expectedSats,
            btcPayoutScriptPubKey: new_vault.btcPayoutScriptPubKey,
            specifiedPayoutAddress: new_vault.specifiedPayoutAddress,
            ownerAddress: new_vault.ownerAddress,
            salt: new_vault.salt,
            confirmationBlocks: new_vault.confirmationBlocks,
            attestedBitcoinBlockHeight: new_vault.attestedBitcoinBlockHeight,
        });

        println!("Vault commitment: {:?}", hex::encode(vault_commitment));

        println!("Created vault: {:?}", new_vault);

        // send double what we need so we have plenty to cover the fee
        let funding_amount = 200_000_000u64;

        // now send some bitcoin to the taker's btc address so we can get a UTXO to spend
        let funding_utxo = devnet
            .bitcoin
            .deal_bitcoin(
                taker_btc_wallet.address.clone(),
                Amount::from_sat(funding_amount),
            ) // 1.5 bitcoin
            .await
            .unwrap();

        let txid = funding_utxo.txid;
        let wallet = taker_btc_wallet;
        let fee_sats = 1000;
        let transaction = funding_utxo.transaction().unwrap();

        // if the predicate is true, we can spend it
        let txvout = transaction
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| {
                output.script_pubkey.as_bytes() == wallet.get_p2wpkh_script().as_bytes()
                    && output.value == funding_amount
            })
            .map(|(index, _)| index as u32)
            .unwrap();

        println!("Funding Transaction: {:?}", transaction);

        println!(
            "Funding UTXO: {:?}",
            hex::encode(
                bitcoincore_rpc_async::bitcoin::util::psbt::serialize::Serialize::serialize(
                    &transaction
                )
            )
        );

        let serialized = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(&transaction);
        let mut reader = serialized.as_slice();
        let canon_bitcoin_tx =
            Transaction::consensus_decode_from_finite_reader(&mut reader).unwrap();
        let canon_txid = canon_bitcoin_tx.compute_txid();
        let canon_deposit_vault =
            sol_types::Types::DepositVault::abi_decode(&new_vault.abi_encode(), false).unwrap();

        // ---4) Taker broadcasts a Bitcoin transaction paying that scriptPubKey---
        let payment_tx = txn_builder::build_rift_payment_transaction(
            &canon_deposit_vault,
            &canon_txid,
            &canon_bitcoin_tx,
            txvout,
            &wallet,
            fee_sats,
        )
        .unwrap();

        let payment_tx_serialized = &mut Vec::new();
        payment_tx.consensus_encode(payment_tx_serialized).unwrap();

        let payment_tx_serialized = payment_tx_serialized.as_slice();

        let current_block_height = devnet.bitcoin.rpc_client.get_block_count().await.unwrap();

        // broadcast it
        let broadcast_tx = devnet
            .bitcoin
            .rpc_client
            .send_raw_transaction(payment_tx_serialized)
            .await
            .unwrap();
        println!("Bitcoin tx sent");

        let payment_tx_id = payment_tx.compute_txid();
        let bitcoin_txid: [u8; 32] = payment_tx_id.as_raw_hash().to_byte_array();

        let swap_block_height = current_block_height + 1;

        // now mine enough blocks for confirmations (1 + 1 additional)
        devnet.bitcoin.mine_blocks(2).await.unwrap();

        // wait for the block height to be included in the data engine
        let swap_leaf = devnet
            .bitcoin
            .data_engine
            .wait_for_block_height(swap_block_height as u32)
            .await
            .unwrap();

        println!("Swap block height (mined): {:?}", swap_block_height);
        println!("Broadcast tx: {:?}", broadcast_tx);

        println!("Payment tx: {:?}", payment_tx);

        // ---5) Generate a "swap proof" referencing that Bitcoin transaction + block inclusion---
        //    In real usage, you'd do a ZK proof. We'll just do a "fake" MMR proof:

        // You'd pass these proofs into e.g. `submitBatchSwapProofWithLightClientUpdate(...)`
        // or just `submitBatchSwapProof(...)` if the chain is already updated. We'll do
        // the simpler route: no real chain update => use submitBatchSwapProof.

        // We'll craft the needed "ProposedSwap" data.
        // See the contract's `SubmitSwapProofParams`.
        use rift_sdk::bindings::Types::{
            DepositVault, ProposedSwap, StorageStrategy, SubmitSwapProofParams,
        };
        // Now we build the Light client update and swap proof

        // TODO: For each MMR update on the contract, store the leaf hash of the tip at that point in the data engine in a new index/table
        // so mmr_hash -> tip_leaf_hash

        // TODO: Build the light client update first
        // 1. Grab the current MMR root from the data engine
        // 2. Find the tip leaf associated with this MMR
        // 3. Validate inclusion in the Bitcoin data engine
        // 4. If not included, jump to step 1. instead grabbing the second to last MMR root, doing this recursively until we find a leaf that is included in the Bitcoin data engine
        // 5. Once we find a leaf that is included, build the light client proof with that leaf as the parent

        let proof_generator = proof_generator_handle.await.unwrap();

        let receipt_logs = receipt.inner.logs();
        // this will have only a VaultsUpdated log
        let vaults_updated_log = RiftExchange::VaultsUpdated::decode_log(
            &receipt_logs
                .iter()
                .find(|log| *log.topic0().unwrap() == RiftExchange::VaultsUpdated::SIGNATURE_HASH)
                .unwrap()
                .inner,
            false,
        )
        .unwrap();

        /*
        #[derive(Debug, Clone, Serialize, Deserialize, Default)]
        pub struct BlockPosition {
            pub header: Header,
            pub leaf: BlockLeaf,
            pub inclusion_proof: MMRProof,
        }
                   // Previous MMR state
            pub current_mmr_root: Digest,
            pub current_mmr_bagged_peak: Digest, // bagged peak of the old MMR, when hashed with the leaf count gives the previous MMR root

            // Block positions
            pub parent: BlockPosition,          // parent of the new chain
            pub parent_retarget: BlockPosition, // retarget block of the parent
            pub current_tip: BlockPosition,    // previous tip of the old MMR

            // New chain data
            pub parent_leaf_peaks: Vec<Digest>, // peaks of the MMR with parent as the tip
            pub disposed_leaf_hashes: Vec<Digest>, // leaves that are being removed from the old MMR => all of the leaves after parent in the old MMR
            pub new_headers: Vec<Header>,

                 */

        let (parent_leaf, parent_leaf_index) = {
            let mmr = devnet.contract_data_engine.indexed_mmr.read().await;
            let leaf_index = mmr.get_leaf_count().await.unwrap() - 1;
            let leaf = mmr
                .get_leaf_by_leaf_index(leaf_index)
                .await
                .unwrap()
                .unwrap();
            (leaf, leaf_index)
        };
        println!("parent_leaf: {:?}", parent_leaf);
        let parent_header: Header = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(
            &devnet
                .bitcoin
                .rpc_client
                .get_block_header(
                    &bitcoincore_rpc_async::bitcoin::BlockHash::from_slice(
                        &parent_leaf
                            .block_hash
                            .iter()
                            .rev()
                            .copied()
                            .collect::<Vec<u8>>(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap(),
        )
        .try_into()
        .unwrap();
        let parent_inclusion_proof = devnet
            .contract_data_engine
            .indexed_mmr
            .read()
            .await
            .get_circuit_proof(parent_leaf_index, None)
            .await
            .unwrap();

        let parent_leaf_peaks = devnet
            .contract_data_engine
            .indexed_mmr
            .read()
            .await
            .get_peaks(Some(map_leaf_index_to_element_index(parent_leaf_index) + 1))
            .await
            .unwrap();

        let parent_retarget_leaf_index = get_retarget_height_from_block_height(parent_leaf.height);
        let parent_retarget_leaf = devnet
            .bitcoin
            .data_engine
            .indexed_mmr
            .read()
            .await
            .get_leaf_by_leaf_index(parent_retarget_leaf_index as usize)
            .await
            .unwrap()
            .unwrap();
        let parent_retarget_header = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(
            &devnet
                .bitcoin
                .rpc_client
                .get_block_header(
                    &bitcoincore_rpc_async::bitcoin::BlockHash::from_slice(
                        &parent_retarget_leaf
                            .block_hash
                            .iter()
                            .rev()
                            .copied()
                            .collect::<Vec<u8>>(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap(),
        )
        .try_into()
        .unwrap();
        let parent_retarget_inclusion_proof = devnet
            .contract_data_engine
            .indexed_mmr
            .read()
            .await
            .get_circuit_proof(parent_retarget_leaf_index as usize, None)
            .await
            .unwrap();

        let first_download_height = parent_leaf.height + 1;
        let last_download_height = devnet
            .bitcoin
            .data_engine
            .indexed_mmr
            .read()
            .await
            .get_leaf_count()
            .await
            .unwrap()
            - 1;

        println!(
            "Downloading headers from {:?} to {:?} [inclusive]",
            first_download_height, last_download_height
        );

        let new_headers = devnet
            .bitcoin
            .rpc_client
            .get_headers_from_block_range(
                first_download_height,
                last_download_height as u32,
                None,
                Some(
                    parent_leaf
                        .block_hash
                        .iter()
                        .rev()
                        .copied()
                        .collect::<Vec<u8>>()
                        .try_into()
                        .unwrap(),
                ),
            )
            .await
            .unwrap()
            .iter()
            .map(|h| {
                let header = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(h);
                header.try_into().unwrap()
            })
            .collect::<Vec<Header>>();

        let chain_transition = ChainTransition {
            current_mmr_root: devnet.contract_data_engine.get_mmr_root().await.unwrap(),
            current_mmr_bagged_peak: devnet
                .contract_data_engine
                .get_mmr_bagged_peak()
                .await
                .unwrap(),

            // the current tip
            parent: BlockPosition {
                header: parent_header,
                leaf: parent_leaf,
                inclusion_proof: parent_inclusion_proof.clone(),
            },
            parent_retarget: BlockPosition {
                header: parent_retarget_header,
                leaf: parent_retarget_leaf,
                inclusion_proof: parent_retarget_inclusion_proof,
            },
            current_tip: BlockPosition {
                header: parent_header,
                leaf: parent_leaf,
                inclusion_proof: parent_inclusion_proof,
            },
            parent_leaf_peaks,
            disposed_leaf_hashes: vec![],
            new_headers,
        };

        /*
        #[derive(Debug, Clone, Serialize, Deserialize, Default)]
        pub struct RiftTransaction {
            // no segwit data serialized bitcoin transaction
            pub txn: Vec<u8>,
            // the vaults reserved for this transaction
            pub reserved_vault: DepositVault,
            // block header where the txn is included
            pub block_header: Header,
            // merkle proof of the txn hash in the block
            pub txn_merkle_proof: Vec<MerkleProofStep>,
        }
        */

        let swap_block_hash = devnet
            .bitcoin
            .rpc_client
            .get_block_hash(swap_block_height as u64)
            .await
            .unwrap();

        let swap_block_header: Header =
            bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(
                &devnet
                    .bitcoin
                    .rpc_client
                    .get_block_header(&swap_block_hash)
                    .await
                    .unwrap(),
            )
            .try_into()
            .unwrap();

        let swap_full_block = devnet
            .bitcoin
            .rpc_client
            .get_block(&swap_block_hash)
            .await
            .unwrap();

        let (txn_merkle_proof, _) = generate_bitcoin_txn_merkle_proof(
            &swap_full_block
                .txdata
                .iter()
                .map(|t| t.txid().to_vec().try_into().unwrap())
                .collect::<Vec<_>>(),
            bitcoin_txid,
        );

        let rift_transaction_input = RiftTransaction {
            txn: serialize_no_segwit(&payment_tx),
            reserved_vault: sol_types::Types::DepositVault::abi_decode(
                new_vault.abi_encode().as_slice(),
                false,
            )
            .unwrap(),
            block_header: swap_block_header,
            txn_merkle_proof,
        };

        let rift_program_input = RiftProgramInput::builder()
            .proof_type(rift_core::giga::RustProofType::Combined)
            .light_client_input(chain_transition)
            .rift_transaction_input(vec![rift_transaction_input])
            .build()
            .unwrap();

        let proof = proof_generator.prove(&rift_program_input).await.unwrap();

        println!(
            "Proved light client update from block {:?} to {:?} and swap bitcoin transaction.\n Proof Info: {:?}",
            first_download_height, last_download_height, proof
        );
        // wait for the block to be included in the data engine

        let swap_mmr_proof = devnet
            .bitcoin
            .data_engine
            .indexed_mmr
            .read()
            .await
            .get_circuit_proof(swap_block_height as usize, None)
            .await
            .unwrap();

        let swap_leaf: sol_types::Types::BlockLeaf = swap_leaf.into();
        let swap_leaf = rift_sdk::bindings::Types::BlockLeaf::abi_decode(
            swap_leaf.abi_encode().as_slice(),
            false,
        )
        .unwrap();

        // We'll do a single-swap array:
        let swap_params = vec![SubmitSwapProofParams {
            swapBitcoinTxid: bitcoin_txid.into(),
            vault: new_vault.clone(),
            storageStrategy: 0, // Append
            localOverwriteIndex: 0,
            swapBitcoinBlockLeaf: swap_leaf.clone(),
            swapBitcoinBlockSiblings: swap_mmr_proof.siblings.iter().map(From::from).collect(),
            swapBitcoinBlockPeaks: swap_mmr_proof.peaks.iter().map(From::from).collect(),
        }];

        // just call verify not in the proof
        let (public_values_simulated, auxiliary_data) =
            rift_program_input.get_auxiliary_light_client_data();

        let block_proof_params = BlockProofParams {
            priorMmrRoot: public_values_simulated.previousMmrRoot,
            newMmrRoot: public_values_simulated.newMmrRoot,
            tipBlockLeaf: rift_sdk::bindings::Types::BlockLeaf::abi_decode(
                public_values_simulated.tipBlockLeaf.abi_encode().as_slice(),
                false,
            )
            .unwrap(),
            compressedBlockLeaves: auxiliary_data.compressed_leaves.into(),
        };

        // We also pass an empty "overwriteSwaps"
        let overwrite_swaps = vec![];

        // The contract function is:
        // Types.SubmitSwapProofParams[] calldata swapParams,
        // Types.BlockProofParams calldata blockProofParams,
        // Types.ProposedSwap[] calldata overwriteSwaps,
        // bytes calldata proof
        // )
        let mock_proof = vec![];

        let swap_proof_call = rift_exchange.submitBatchSwapProofWithLightClientUpdate(
            swap_params,
            block_proof_params,
            overwrite_swaps,
            mock_proof.into(),
        );
        let swap_proof_calldata = swap_proof_call.calldata().clone();

        let swap_proof_tx = maker_evm_provider
            .send_transaction(swap_proof_call.into_transaction_request())
            .await;

        let swap_proof_receipt = match swap_proof_tx {
            Ok(tx) => {
                let receipt = tx.get_receipt().await.expect("No swap proof tx receipt");
                println!("Swap proof receipt: {:?}", receipt);
                receipt
            }
            Err(tx_error) => {
                println!("Swap proof submission error: {:?}", tx_error);
                let block_height = devnet
                    .ethereum
                    .funded_provider
                    .get_block_number()
                    .await
                    .map_err(|e| eyre::eyre!(e))
                    .unwrap();

                let data = hex::encode(swap_proof_calldata);
                let from = taker_evm_address.to_string();
                let to = rift_exchange.address().to_string();
                println!(
                    "To debug failed swap proof submission run: cast call {} --from {} --data {} --trace --block {} --rpc-url {}",
                    to,
                    from,
                    data,
                    block_height,
                    devnet.ethereum.anvil.endpoint()
                );
                // Allow for debugging before panic
                signal::ctrl_c().await.unwrap();
                panic!("Swap proof submission failed");
            }
        };

        let receipt_logs = swap_proof_receipt.inner.logs();
        // this will have only a VaultsUpdated log
        let binding = RiftExchange::SwapsUpdated::decode_log(
            &receipt_logs
                .iter()
                .find(|log| *log.topic0().unwrap() == RiftExchange::SwapsUpdated::SIGNATURE_HASH)
                .unwrap()
                .inner,
            false,
        )
        .unwrap();
        let proposed_swap = binding.data.swaps.first().unwrap();

        // First, get the MMR proof for the swap block (this proof contains the leaf data, siblings, and peaks)
        let swap_mmr_proof = devnet
            .bitcoin
            .data_engine
            .indexed_mmr
            .read()
            .await
            .get_circuit_proof(swap_block_height as usize, None)
            .await
            .expect("Failed to get swap block proof");

        // Also, get the current tip proof (used here to provide the tip block height)
        let tip_mmr_proof = devnet
            .bitcoin
            .data_engine
            .indexed_mmr
            .read()
            .await
            .get_circuit_proof(swap_block_height as usize + 1, None)
            .await
            .expect("Failed to get tip block proof");

        // Now, construct the ReleaseLiquidityParams.
        // The structure (defined in your Types) is as follows:
        //   struct ReleaseLiquidityParams {
        //       swap: ProposedSwap,
        //       swapBlockChainwork: U256,
        //       swapBlockHeight: u32,
        //       bitcoinSwapBlockSiblings: Vec<Digest>,
        //       bitcoinSwapBlockPeaks: Vec<Digest>,
        //       utilizedVault: DepositVault,
        //       tipBlockHeight: u32,
        //   }
        let release_params = rift_sdk::bindings::Types::ReleaseLiquidityParams {
            swap: proposed_swap.clone(),
            swapBlockChainwork: swap_leaf.cumulativeChainwork,
            swapBlockHeight: swap_leaf.height.clone(),
            bitcoinSwapBlockSiblings: swap_mmr_proof.siblings.iter().map(From::from).collect(),
            bitcoinSwapBlockPeaks: swap_mmr_proof.peaks.iter().map(From::from).collect(),
            utilizedVault: new_vault.clone(),
            tipBlockHeight: (devnet.contract_data_engine.get_leaf_count().await.unwrap() - 1)
                as u32,
        };

        // warp timestamp to 1 second after release timestamp
        devnet
            .ethereum
            .funded_provider
            .anvil_set_next_block_timestamp(release_params.swap.liquidityUnlockTimestamp + 1)
            .await
            .unwrap();

        // Build the release liquidity call. Assume `release_params_array` is a Vec of ReleaseLiquidityParams.
        let release_liquidity_call = rift_exchange.releaseLiquidityBatch(vec![release_params]);

        // Extract the calldata for debugging
        let release_liquidity_calldata = release_liquidity_call.calldata().clone();

        // Send the transaction using the maker's EVM provider.
        let release_liquidity_tx = maker_evm_provider
            .send_transaction(release_liquidity_call.into_transaction_request())
            .await;

        // Handle the result with debugging output on error.
        let release_liquidity_receipt = match release_liquidity_tx {
            Ok(tx) => {
                let receipt = tx
                    .get_receipt()
                    .await
                    .expect("No release liquidity tx receipt");
                println!("Release liquidity receipt: {:?}", receipt);
                receipt
            }
            Err(tx_error) => {
                println!("Release liquidity submission error: {:?}", tx_error);
                // Fetch current block height for debug info.
                let block_height = devnet
                    .ethereum
                    .funded_provider
                    .get_block_number()
                    .await
                    .map_err(|e| eyre::eyre!(e))
                    .unwrap();

                let data = hex::encode(release_liquidity_calldata);
                let from = taker_evm_address.to_string();
                let to = rift_exchange.address().to_string();
                println!(
            "To debug failed release liquidity submission run: cast call {} --from {} --data {} --trace --block {} --rpc-url {}",
            to,
            from,
            data,
            block_height,
            devnet.ethereum.anvil.endpoint()
        );
                // Allow for debugging before panicking.
                signal::ctrl_c().await.unwrap();
                panic!("Release liquidity submission failed");
            }
        };

        // If all steps got here w/o revert, we assume success:
        println!("All steps in the end-to-end flow completed successfully!");
    }
}
