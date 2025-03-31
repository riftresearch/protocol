use super::*;
use ::bitcoin::consensus::{Decodable, Encodable};
use ::bitcoin::hashes::serde::Serialize;
use ::bitcoin::hashes::Hash;
use ::bitcoin::{Amount, Transaction};
use accumulators::mmr::map_leaf_index_to_element_index;
use alloy::eips::eip6110::DEPOSIT_REQUEST_TYPE;
use alloy::hex;
use alloy::network::EthereumWallet;
use alloy::primitives::utils::{format_ether, format_units};
use alloy::primitives::{Address as EvmAddress, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder, WalletProvider, WsConnect};
use alloy::signers::local::LocalSigner;
use alloy::sol_types::{SolEvent, SolValue};
use bitcoin::hashes::serde::Deserialize;
use bitcoin_light_client_core::hasher::Keccak256Hasher;
use bitcoin_light_client_core::leaves::BlockLeaf as CoreBlockLeaf;
use bitcoin_light_client_core::light_client::Header;
use bitcoin_light_client_core::mmr::MMRProof as CircuitMMRProof;
use bitcoin_light_client_core::{ChainTransition, ProvenLeaf, VerifiedBlock};
use bitcoincore_rpc_async::bitcoin::hashes::Hash as BitcoinHash;
use bitcoincore_rpc_async::bitcoin::BlockHash;
use bitcoincore_rpc_async::RpcApi;
use devnet::RiftDevnet;
use rift_core::giga::RiftProgramInput;
use rift_core::spv::generate_bitcoin_txn_merkle_proof;
use rift_core::vaults::hash_deposit_vault;
use rift_core::RiftTransaction;
use rift_sdk::bitcoin_utils::BitcoinClientExt;
use rift_sdk::indexed_mmr::client_mmr_proof_to_circuit_mmr_proof;
use rift_sdk::proof_generator::{ProofGeneratorType, RiftProofGenerator};
use rift_sdk::txn_builder::{self, serialize_no_segwit, P2WPKHBitcoinWallet};
use rift_sdk::{
    create_websocket_provider, get_retarget_height_from_block_height, right_pad_to_25_bytes,
    DatabaseLocation,
};
use sol_bindings::Types::{DepositLiquidityParams, ReleaseLiquidityParams, SubmitSwapProofParams};
use sol_bindings::{
    RiftExchange, Types::BlockLeaf, Types::BlockProofParams, Types::ProofPublicInput,
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
#[serial_test::serial]
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

    let maker_btc_wallet =
        P2WPKHBitcoinWallet::from_secret_bytes(&maker_secret_bytes, ::bitcoin::Network::Regtest);

    let taker_btc_wallet =
        P2WPKHBitcoinWallet::from_secret_bytes(&taker_secret_bytes, ::bitcoin::Network::Regtest);

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
    let (devnet, _funded_sats) = RiftDevnet::builder()
        .using_bitcoin(true)
        .funded_evm_address(maker_evm_address.to_string())
        .data_engine_db_location(DatabaseLocation::InMemory)
        .build()
        .await
        .unwrap();

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

    // We can skip real MMR proofs; for dev/test, we can pass dummy MMR proof data or a known "safe block."
    // For example, we'll craft a dummy "BlockLeaf" that the contract won't reject:
    let (safe_leaf, safe_siblings, safe_peaks) =
        devnet.contract_data_engine.get_tip_proof().await.unwrap();

    let mmr_root = devnet.contract_data_engine.get_mmr_root().await.unwrap();

    let safe_leaf: sol_bindings::Types::BlockLeaf = safe_leaf.into();

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

    let maker_btc_wallet_script_pubkey = maker_btc_wallet.get_p2wpkh_script();

    let padded_script = right_pad_to_25_bytes(maker_btc_wallet_script_pubkey.as_bytes());

    let deposit_params = DepositLiquidityParams {
        depositOwnerAddress: maker_evm_address,
        specifiedPayoutAddress: taker_evm_address,
        depositAmount: deposit_amount,
        expectedSats: expected_sats,
        btcPayoutScriptPubKey: padded_script.into(),
        depositSalt: [0x44; 32].into(), // this can be anything
        confirmationBlocks: 2,          // require 2 confirmations (1 block to mine + 1 additional)
        // TODO: This is hellacious, remove the 3 different types for BlockLeaf somehow
        safeBlockLeaf: safe_leaf,
        safeBlockSiblings: safe_siblings.iter().map(From::from).collect(),
        safeBlockPeaks: safe_peaks.iter().map(From::from).collect(),
    };
    println!("Deposit params: {:?}", deposit_params);

    let deposit_call = rift_exchange.depositLiquidity(deposit_params);

    let deposit_calldata = deposit_call.calldata();

    let deposit_transaction_request = deposit_call.clone().into_transaction_request();

    let deposit_tx = maker_evm_provider
        .send_transaction(deposit_transaction_request)
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
    let vault_commitment = hash_deposit_vault(&new_vault);

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
                && output.value == Amount::from_sat(funding_amount)
        })
        .map(|(index, _)| index as u32)
        .unwrap();

    println!("Funding Transaction: {:?}", transaction);

    println!(
        "Funding UTXO: {:?}",
        hex::encode(&serialize_no_segwit(&transaction).unwrap())
    );

    let serialized = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(&transaction);
    let mut reader = serialized.as_slice();
    let canon_bitcoin_tx = Transaction::consensus_decode_from_finite_reader(&mut reader).unwrap();
    let canon_txid = canon_bitcoin_tx.compute_txid();

    // ---4) Taker broadcasts a Bitcoin transaction paying that scriptPubKey---
    let payment_tx = txn_builder::build_rift_payment_transaction(
        &new_vault,
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

    let mut new_block_subscription = devnet.bitcoin.data_engine.subscribe_to_new_blocks();

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

    let swap_leaf = loop {
        let new_block_leaf = new_block_subscription.recv().await.unwrap();
        println!("New block leaf: {:?}", new_block_leaf);
        if new_block_leaf.height == swap_block_height as u32 {
            break new_block_leaf;
        }
    };

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
        let mmr = devnet
            .contract_data_engine
            .checkpointed_block_tree
            .read()
            .await;
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
        .checkpointed_block_tree
        .read()
        .await
        .get_circuit_proof(parent_leaf_index, None)
        .await
        .unwrap();

    let parent_leaf_peaks = devnet
        .contract_data_engine
        .checkpointed_block_tree
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
        .checkpointed_block_tree
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
            100,
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
        parent: VerifiedBlock {
            header: parent_header,
            mmr_data: ProvenLeaf {
                leaf: parent_leaf,
                proof: parent_inclusion_proof.clone(),
            },
        },
        parent_retarget: VerifiedBlock {
            header: parent_retarget_header,
            mmr_data: ProvenLeaf {
                leaf: parent_retarget_leaf,
                proof: parent_retarget_inclusion_proof,
            },
        },
        current_tip: ProvenLeaf {
            leaf: parent_leaf,
            proof: parent_inclusion_proof,
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

    let swap_block_header: Header = bitcoincore_rpc_async::bitcoin::consensus::encode::serialize(
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
            .map(|t| t.compute_txid().as_raw_hash().to_byte_array())
            .collect::<Vec<_>>(),
        bitcoin_txid,
    );

    let rift_transaction_input = RiftTransaction {
        txn: serialize_no_segwit(&payment_tx).unwrap(),
        reserved_vault: new_vault.clone(),
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

    let swap_leaf: sol_bindings::Types::BlockLeaf = swap_leaf.into();

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
        tipBlockLeaf: public_values_simulated.tipBlockLeaf,
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
    let release_params = ReleaseLiquidityParams {
        swap: proposed_swap.clone(),
        bitcoinSwapBlockSiblings: swap_mmr_proof.siblings.iter().map(From::from).collect(),
        bitcoinSwapBlockPeaks: swap_mmr_proof.peaks.iter().map(From::from).collect(),
        utilizedVault: new_vault.clone(),
        tipBlockHeight: (devnet.contract_data_engine.get_leaf_count().await.unwrap() - 1) as u32,
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
