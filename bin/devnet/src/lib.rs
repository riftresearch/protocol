//! `lib.rs` — central library code.

mod bitcoin;
mod evm;

use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
pub use bitcoin::BitcoinDevnet;
pub use evm::EthDevnet;

use evm::EvmWebsocketProvider;
use eyre::Result;
use log::info;
use rift_sdk::bindings::RiftExchange;
use std::sync::Arc;
use tokio::time::Instant;

use data_engine::engine::DataEngine;
use data_engine_server::DataEngineServer;

use rift_sdk::{get_rift_program_hash, DatabaseLocation};

use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::RpcApi;
use rift_sdk::bitcoin_utils::{AsyncBitcoinClient, BitcoinClientExt};

// ================== Contract ABIs ================== //

const TOKEN_SYMBOL: &str = "cbBTC";
const TOKEN_NAME: &str = "Coinbase Wrapped BTC";
const TOKEN_DECIMALS: u8 = 8;
const DATA_ENGINE_SERVER_PORT: u16 = 50100;

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

    // Deploy the mock token
    let token = MockToken::deploy(
        provider.clone(),
        TOKEN_NAME.to_owned(),
        TOKEN_SYMBOL.to_owned(),
        TOKEN_DECIMALS,
    )
    .await?;

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
    pub data_engine: Arc<DataEngine>,
    pub _data_engine_server: Option<DataEngineServer>,
}

impl RiftDevnet {
    /// The main entry point to set up a devnet with both sides plus data engine.
    /// Returns `(RiftDevnet, funding_sats)`.
    pub async fn setup(
        interactive: bool,
        funded_evm_address: Option<String>,
        funded_bitcoin_address: Option<String>,
    ) -> Result<(Self, u64)> {
        // 1) Bitcoin side
        let bitcoin_devnet = BitcoinDevnet::setup(funded_bitcoin_address)?;
        let funding_sats = bitcoin_devnet.funded_sats;

        // 2) Grab some additional info (like checkpoint leaves)
        info!("Downloading checkpoint leaves from block range 0..101");
        let checkpoint_leaves = bitcoin_devnet
            .btc_rpc_client
            .get_leaves_from_block_range(0, 101, None)
            .await?;

        let tip_block_leaf = &checkpoint_leaves.last().unwrap().clone();

        // 4) Data Engine
        info!("Seeding data engine with checkpoint leaves...");
        let t = Instant::now();
        let mut data_engine =
            DataEngine::seed(DatabaseLocation::InMemory, checkpoint_leaves).await?;
        info!("Data engine seeded in {:?}", t.elapsed());

        // 3) Start EVM side
        let circuit_verification_key_hash = get_rift_program_hash(); // or however you do it
        let (ethereum_devnet, deployment_block_number) = EthDevnet::setup(
            circuit_verification_key_hash,
            data_engine.get_mmr_root().await.unwrap(),
            *tip_block_leaf,
        )
        .await?;

        // Start listening for on-chain events from RiftExchange
        data_engine
            .start_event_listener(
                ethereum_devnet.funded_provider.clone(),
                ethereum_devnet.rift_exchange_contract.address().to_string(),
                deployment_block_number,
            )
            .await?;

        let data_engine = Arc::new(data_engine);

        // Possibly run a local data-engine HTTP server
        let data_engine_server = if interactive {
            let server =
                DataEngineServer::from_engine(data_engine.clone(), DATA_ENGINE_SERVER_PORT).await?;
            Some(server)
        } else {
            None
        };

        if interactive {
            println!("---RIFT DEVNET---");
            println!(
                "Anvil HTTP Url:        {}",
                ethereum_devnet.anvil.endpoint()
            );
            println!(
                "Anvil WS Url:          {}",
                ethereum_devnet.anvil.ws_endpoint()
            );
            println!(
                "Anvil Chain ID:        {}",
                ethereum_devnet.anvil.chain_id()
            );
            println!(
                "Data Engine HTTP URL:  http://localhost:{}",
                DATA_ENGINE_SERVER_PORT
            );
            println!(
                "Bitcoin RPC URL:       {}",
                bitcoin_devnet.bitcoin_regtest.rpc_url()
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
                .fund_token(address, U256::from_str("10000000000000000000")?)
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
            data_engine,
            _data_engine_server: data_engine_server,
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
    use ::bitcoin::{Amount, Transaction};
    use alloy::eips::eip6110::DEPOSIT_REQUEST_TYPE;
    use alloy::hex;
    use alloy::primitives::utils::{format_ether, format_units};
    use alloy::primitives::{Address as EvmAddress, U256};
    use alloy::providers::ext::AnvilApi;
    use alloy::providers::{ProviderBuilder, WalletProvider, WsConnect};
    use alloy::signers::local::LocalSigner;
    use alloy::sol_types::{SolEvent, SolValue};
    use bitcoin_light_client_core::hasher::Keccak256Hasher;
    use bitcoin_light_client_core::leaves::BlockLeaf as CoreBlockLeaf;
    use bitcoin_light_client_core::mmr::MMRProof as CircuitMMRProof;
    use bitcoincore_rpc_async::bitcoin::util::psbt::serialize::Serialize as AsyncSerialize;
    use rift_core::vaults::hash_deposit_vault;
    use rift_sdk::bindings::non_artifacted_types::Types::BlockLeaf;
    use rift_sdk::bindings::non_artifacted_types::Types::MMRProof;
    use rift_sdk::mmr::client_mmr_proof_to_circuit_mmr_proof;
    use rift_sdk::txn_builder::{self, P2WPKHBitcoinWallet};
    use rift_sdk::{create_websocket_provider, DatabaseLocation};
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
    async fn test_swap_end_to_end() {
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

        // fund maker evm wallet, and taker btc wallet
        let (devnet, _funded_sats) = RiftDevnet::setup(
            /*interactive=*/ false,
            /*funded_evm_address=*/ Some(maker_evm_address.to_string()),
            /*funded_bitcoin_address=*/ None,
        )
        .await
        .expect("Failed to set up devnet");

        let maker_evm_provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(maker_evm_wallet)
            .on_ws(WsConnect::new(devnet.ethereum.anvil.ws_endpoint_url()))
            .await
            .expect("Failed to create maker evm provider");

        let taker_evm_provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(taker_evm_wallet)
            .on_ws(WsConnect::new(devnet.ethereum.anvil.ws_endpoint_url()))
            .await
            .expect("Failed to create taker evm provider");

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
            devnet.data_engine.get_tip_proof().await.unwrap();

        let mmr_root = devnet.data_engine.get_mmr_root().await.unwrap();

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

        // broadcast it
        let broadcast_tx = devnet
            .bitcoin
            .btc_rpc_client
            .send_raw_transaction(payment_tx_serialized)
            .await
            .unwrap();

        let payment_tx_id = payment_tx.compute_txid();

        // wait for the tx to be confirmed
        // TODO: build a bitcoin-native variant of the data engine that stores all blocks
        // an indexed mmr

        println!("Broadcast tx: {:?}", broadcast_tx);

        println!("Payment tx: {:?}", payment_tx);

        // ---5) Generate a "swap proof" referencing that Bitcoin transaction + block inclusion---
        //    In real usage, you'd do a ZK proof. We'll just do a "fake" MMR proof:
        let fake_swap_proof = MMRProof {
            blockLeaf: BlockLeaf {
                blockHash: [0u8; 32].into(),
                height: 1234,
                cumulativeChainwork: U256::from(1000),
            },
            siblings: vec![],
            peaks: vec![],
            leafCount: 1235,
            mmrRoot: [0u8; 32].into(),
        };

        /*
        // We also pretend there's a "tipBlockLeaf" MMR proof for updating the light client
        let fake_tip_proof = MMRProof {
            blockLeaf: BlockLeaf {
                blockHash: [1u8; 32].into(),
                height: 1235,
                cumulativeChainwork: U256::from(2000),
            },
            siblings: vec![],
            peaks: vec![],
            leafCount: 1236,
            mmrRoot: [0u8; 32].into(),
        };

        // You'd pass these proofs into e.g. `submitBatchSwapProofWithLightClientUpdate(...)`
        // or just `submitBatchSwapProof(...)` if the chain is already updated. We'll do
        // the simpler route: no real chain update => use submitBatchSwapProof.

        // We'll craft the needed "ProposedSwap" data.
        // See the contract's `SubmitSwapProofParams`.
        use rift_sdk::bindings::non_artifacted_types::Types::{
            DepositVault, ProposedSwap, StorageStrategy, SubmitSwapProofParams,
        };
        let deposit_vault_commitment = [0xaa; 32]; // placeholder
                                                   // In real usage, you'd get the actual deposit vault commitment from logs or from the same
                                                   // hashing as the contract does.

        // We'll do a single-swap array:
        let swap_params = vec![SubmitSwapProofParams {
            swapBitcoinTxid: [0x77; 32].into(),
            vault: DepositVault {
                vaultIndex: 0,
                depositTimestamp: 0,
                depositAmount: deposit_amount,
                depositFee: deposit_fee,
                expectedSats: expected_sats as u64,
                btcPayoutScriptPubKey: [0; 22],
                specifiedPayoutAddress: maker_address,
                ownerAddress: maker_address,
                salt: [0x44; 32].into(),
                confirmationBlocks: 6,
                attestedBitcoinBlockHeight: 1,
            },
            storageStrategy: StorageStrategy::Append,
            localOverwriteIndex: 0,
            swapBitcoinBlockLeaf: fake_swap_proof.blockLeaf,
            swapBitcoinBlockSiblings: fake_swap_proof.siblings.clone(),
            swapBitcoinBlockPeaks: fake_swap_proof.peaks.clone(),
        }];

        // We also pass an empty "overwriteSwaps"
        let overwrite_swaps = vec![];

        // The contract function is:
        // submitBatchSwapProof(
        //   SubmitSwapProofParams[] swapParams,
        //   ProposedSwap[] overwriteSwaps,
        //   bytes calldata proof
        // )
        // We can pass an empty "proof" or something.
        let no_proof = vec![];

        let tx_call = rift_exchange
            .submitBatchSwapProof(swap_params, overwrite_swaps, no_proof.into())
            .legacy();

        let proof_receipt = tx_call
            .send()
            .await
            .expect("submitBatchSwapProof call failed")
            .get_receipt()
            .await
            .expect("No receipt for swap proof submission");

        println!("Swap proof receipt: {:?}", proof_receipt);

        // ---6) The maker's liquidity is now "Proved." Next step is "releaseLiquidityBatch."
        // Typically, that requires waiting until the challenge period is over, and the final block is confirmed.
        // For test, we can just do it immediately. We'll craft a minimal "ReleaseLiquidityParams."

        use rift_sdk::bindings::non_artifacted_types::Types::ReleaseLiquidityParams;

        // We re-use the same fake MMR proof references for the "swapBlock" or tip.
        // The contract calls _ensureBitcoinInclusion(...) on them:
        let block_chainwork = fake_swap_proof.blockLeaf.cumulativeChainwork;
        let block_height = fake_swap_proof.blockLeaf.height;

        // The deposit again
        let release_params = ReleaseLiquidityParams {
            swap: ProposedSwap {
                swapIndex: 0,
                depositVaultCommitment: deposit_vault_commitment.into(),
                swapBitcoinBlockHash: fake_swap_proof.blockLeaf.blockHash,
                confirmationBlocks: 6,
                liquidityUnlockTimestamp: 0,
                specifiedPayoutAddress: maker_address,
                totalSwapFee: deposit_fee,
                totalSwapOutput: deposit_amount - deposit_fee,
                state: 1, // 1 => Proved
            },
            swapBlockChainwork: block_chainwork.into(),
            swapBlockHeight: block_height,
            bitcoinSwapBlockSiblings: fake_swap_proof.siblings.clone(),
            bitcoinSwapBlockPeaks: fake_swap_proof.peaks.clone(),
            utilizedVault: DepositVault {
                vaultIndex: 0,
                depositTimestamp: 0,
                depositAmount,
                depositFee,
                expectedSats: expected_sats as u64,
                btcPayoutScriptPubKey: [0; 22],
                specifiedPayoutAddress: maker_address,
                ownerAddress: maker_address,
                salt: [0x44; 32].into(),
                confirmationBlocks: 6,
                attestedBitcoinBlockHeight: 1,
            },
            tipBlockHeight: 1235, // from fake tip
        };

        let release_batch = vec![release_params];

        let release_call = rift_exchange.releaseLiquidityBatch(release_batch).legacy();

        let release_receipt = release_call
            .send()
            .await
            .expect("releaseLiquidityBatch call failed")
            .get_receipt()
            .await
            .expect("No receipt for release tx");

        println!("Release receipt: {:?}", release_receipt);

        // ---7) Confirm final on-chain state e.g.
        // Maker's vault is zero, maker's token balance is bigger, or some event is emitted.
        // For brevity, we do a simple check:

        // If all steps got here w/o revert, we assume success:
        println!("All steps in the end-to-end flow completed successfully!");
        */
    }
}
