use crate::test_utils::MultichainAccount;

use super::*;
use alloy::eips::eip6110::DEPOSIT_REQUEST_TYPE;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::Log as AlloyLog;
use alloy::rpc::types::Log;
use alloy::signers::local::LocalWallet;
use alloy::sol_types::SolEvent;
use alloy_primitives::{FixedBytes, LogData, B256};
use alloy_sol_types::SolValue;
use devnet::RiftDevnet;
use eyre::Result;
use hex;
use log::{debug, error, info, warn};
use market_maker::auction_claimer::{
    calculate_optimal_claim_block, extract_auction_from_log, AuctionClaimer, AuctionClaimerConfig,
    PendingAuction,
};
use rift_sdk::{create_websocket_wallet_provider, DatabaseLocation};
use sol_bindings::{
    AuctionUpdated, BTCDutchAuctionHouseInstance, DutchAuction, DutchAuctionParams,
    MappingWhitelistInstance, RiftExchangeInstance,
};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::{cmp::Reverse, collections::BinaryHeap};
use tokio::sync::{mpsc, Mutex};

// Helpers
fn create_test_auction(
    index: u64,
    deposit_amount: u64,
    start_block: u64,
    start_btc_out: u64,
    end_btc_out: u64,
    decay_blocks: u64,
    deadline: u64,
    whitelist_address: Address,
    state: u8,
) -> DutchAuction {
    DutchAuction {
        index: U256::from(index),
        baseCreateOrderParams: sol_bindings::BTCDutchAuctionHouse::BaseCreateOrderParams {
            owner: Address::ZERO,
            bitcoinScriptPubKey: vec![0x00, 0x14].into(),
            salt: FixedBytes::from([0u8; 32]),
            confirmationBlocks: 2,
            safeBlockLeaf: sol_bindings::BTCDutchAuctionHouse::BlockLeaf {
                blockHash: FixedBytes::from([0u8; 32]),
                height: 100,
                cumulativeChainwork: U256::ZERO,
            },
        },
        depositAmount: U256::from(deposit_amount),
        startBlock: U256::from(start_block),
        startTimestamp: U256::from(1000),
        state,
        dutchAuctionParams: DutchAuctionParams {
            startBtcOut: U256::from(start_btc_out),
            endBtcOut: U256::from(end_btc_out),
            decayBlocks: U256::from(decay_blocks),
            deadline: U256::from(deadline),
            fillerWhitelistContract: whitelist_address,
        },
    }
}

fn create_log_from_auction(auction: &DutchAuction) -> Log {
    // Create event with the auction
    let event = AuctionUpdated {
        auction: auction.clone(),
    };

    // Encode event data
    let event_data = event.encode_data();
    let topic = AuctionUpdated::SIGNATURE_HASH;

    // Make log data
    let log_data = LogData::new_unchecked(vec![topic.into()], event_data.into());

    // Create and return the log
    Log {
        inner: alloy_primitives::Log {
            address: Address::ZERO,
            data: log_data,
        },
        block_hash: Some(FixedBytes::from([1u8; 32])),
        block_number: Some(100),
        block_timestamp: Some(1200),
        transaction_hash: Some(FixedBytes::from([2u8; 32])),
        transaction_index: Some(0),
        log_index: Some(0),
        removed: false,
    }
}

/// Add a maker to a whitelist contract
async fn add_maker_to_whitelist(
    provider: &DynProvider,
    maker_address: Address,
    whitelist_address: Address,
) -> bool {
    let whitelist_instance = MappingWhitelistInstance::new(whitelist_address, provider.clone());

    match whitelist_instance
        .addToWhitelist(maker_address)
        .call()
        .await
    {
        Ok(_) => {
            debug!("Successfully added maker to whitelist");
            true
        }
        Err(e) => {
            error!("Error adding to whitelist: {:?}", e);
            false
        }
    }
}

#[tokio::test]
async fn test_calculate_optimal_claim_block_edge_cases() {
    // 0 spread_bps returns None
    let auction1 = create_test_auction(
        1,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let result1 = calculate_optimal_claim_block(&auction1, 0, 10, 10, 120);
    assert!(result1.is_none(), "Zero spread_bps should return None");

    // Current block >= deadline returns None
    let auction2 = create_test_auction(
        2,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let result2 = calculate_optimal_claim_block(&auction2, 50, 10, 10, 1000);
    assert!(
        result2.is_none(),
        "Current block >= deadline should return None"
    );

    // Zero decay blocks but profitable returns current block
    let auction3 = create_test_auction(
        3,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        1000,          // end_btc_out
        0,             // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let result3 = calculate_optimal_claim_block(&auction3, 10, 5, 5, 120);
    assert_eq!(
        result3,
        Some(120),
        "Zero decay blocks but profitable should return current block"
    );

    // Zero decay blocks and not profitable returns None
    let auction4 = create_test_auction(
        4,             // index
        800,           // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        1000,          // end_btc_out
        0,             // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let result4 = calculate_optimal_claim_block(&auction4, 50, 10, 10, 120);
    assert!(
        result4.is_none(),
        "Zero decay blocks and not profitable should return None"
    );

    // Testing whitelist contracts
    let whitelist_contract_address =
        Address::from_str("0x1111111111111111111111111111111111111111").unwrap();

    let maker = MultichainAccount::new(1);
    let hypernode_account = MultichainAccount::new(2);

    let (devnet, _funded_sats) = match RiftDevnet::builder()
        .using_bitcoin(true)
        .funded_evm_address(maker.ethereum_address.to_string())
        .data_engine_db_location(DatabaseLocation::InMemory)
        .build()
        .await
    {
        Ok(result) => result,
        Err(e) => {
            println!("Error building devnet: {:?}", e);
            return;
        }
    };

    let evm_ws_rpc = devnet.ethereum.anvil.ws_endpoint_url().to_string();
    let private_key = hex::encode(hypernode_account.secret_bytes);

    let evm_rpc_with_wallet = match create_websocket_wallet_provider(
        &evm_ws_rpc,
        match hex::decode(&private_key) {
            Ok(decoded) => match decoded.try_into() {
                Ok(key) => key,
                Err(_) => {
                    println!("Invalid private key length");
                    return;
                }
            },
            Err(e) => {
                println!("Error decoding key: {:?}", e);
                return;
            }
        },
    )
    .await
    {
        Ok(provider) => Arc::new(provider),
        Err(e) => {
            println!("Error creating websocket provider: {:?}", e);
            return;
        }
    };

    let provider = evm_rpc_with_wallet.clone().erased();

    // Add maker to whitelist
    // probably remove whitelist, don't need it for this test
    let whitelist_added = add_maker_to_whitelist(
        &provider,
        maker.ethereum_address,
        whitelist_contract_address,
    )
    .await;
    assert!(whitelist_added, "Failed to add maker to whitelist");

    let auction5 = create_test_auction(
        5,                          // index
        10000,                      // deposit_amount
        100,                        // start_block
        1000,                       // start_btc_out
        900,                        // end_btc_out
        100,                        // decay_blocks
        1000,                       // deadline
        whitelist_contract_address, // whitelist
        0,                          // Created state
    );

    let result5 = calculate_optimal_claim_block(&auction5, 10, 5, 5, 120);
    assert_eq!(
        result5,
        Some(120),
        "Whitelist should not affect profitability calculation"
    );
}

#[test]
fn test_pending_auction_priority_queue() {
    let auction1 = create_test_auction(
        1,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let auction2 = create_test_auction(
        2,             // index
        9000,          // deposit_amount
        100,           // start_block
        900,           // start_btc_out
        800,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let auction3 = create_test_auction(
        3,             // index
        8000,          // deposit_amount
        100,           // start_block
        800,           // start_btc_out
        700,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    // Should pop in order of claim block (smallest first)
    let mut queue = BinaryHeap::new();
    queue.push(Reverse(PendingAuction {
        auction: auction1.clone(),
        claim_at_block: 150,
    }));
    queue.push(Reverse(PendingAuction {
        auction: auction2.clone(),
        claim_at_block: 120,
    }));
    queue.push(Reverse(PendingAuction {
        auction: auction3.clone(),
        claim_at_block: 180,
    }));

    assert_eq!(
        queue.pop().unwrap().0.claim_at_block,
        120,
        "Should pop auction with lowest claim block first"
    );
    assert_eq!(
        queue.pop().unwrap().0.claim_at_block,
        150,
        "Should pop auction with middle claim block second"
    );
    assert_eq!(
        queue.pop().unwrap().0.claim_at_block,
        180,
        "Should pop auction with highest claim block last"
    );
    assert!(
        queue.is_empty(),
        "Queue should be empty after popping all elements"
    );

    // Auctions with same claim block
    let pending4 = PendingAuction {
        auction: auction1.clone(),
        claim_at_block: 200,
    };

    let pending5 = PendingAuction {
        auction: auction2.clone(),
        claim_at_block: 200,
    };

    let mut queue = BinaryHeap::new();
    queue.push(Reverse(pending4.clone()));
    queue.push(Reverse(pending5.clone()));

    let popped1 = queue.pop().unwrap().0;
    let popped2 = queue.pop().unwrap().0;

    assert_eq!(
        popped1.claim_at_block, 200,
        "First popped auction should have claim_at_block 200"
    );
    assert_eq!(
        popped2.claim_at_block, 200,
        "Second popped auction should have claim_at_block 200"
    );
    assert!(
        queue.is_empty(),
        "Queue should be empty after popping both elements"
    );
}

#[tokio::test]
async fn test_auction_whitelist_case() {
    let whitelist_address =
        Address::from_str("0x1111111111111111111111111111111111111111").unwrap();

    let maker = MultichainAccount::new(1);
    let hypernode_account = MultichainAccount::new(2);

    let (devnet, _funded_sats) = match RiftDevnet::builder()
        .using_bitcoin(true)
        .funded_evm_address(maker.ethereum_address.to_string())
        .data_engine_db_location(DatabaseLocation::InMemory)
        .build()
        .await
    {
        Ok(result) => result,
        Err(e) => {
            println!("Error building devnet: {:?}", e);
            return;
        }
    };

    let evm_ws_rpc = devnet.ethereum.anvil.ws_endpoint_url().to_string();
    let private_key = hex::encode(hypernode_account.secret_bytes);

    let evm_rpc_with_wallet = match create_websocket_wallet_provider(
        &evm_ws_rpc,
        match hex::decode(&private_key) {
            Ok(decoded) => match decoded.try_into() {
                Ok(key) => key,
                Err(_) => {
                    println!("Invalid private key length");
                    return;
                }
            },
            Err(e) => {
                println!("Error decoding key: {:?}", e);
                return;
            }
        },
    )
    .await
    {
        Ok(provider) => Arc::new(provider),
        Err(e) => {
            println!("Error creating websocket provider: {:?}", e);
            return;
        }
    };

    let provider = evm_rpc_with_wallet.clone().erased();

    // Add maker to whitelist
    let whitelist_added =
        add_maker_to_whitelist(&provider, maker.ethereum_address, whitelist_address).await;
    assert!(whitelist_added, "Failed to add maker to whitelist");

    let non_whitelist_auction = create_test_auction(
        1,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let whitelist_auction = create_test_auction(
        2,                 // index
        10000,             // deposit_amount
        100,               // start_block
        1000,              // start_btc_out
        900,               // end_btc_out
        100,               // decay_blocks
        1000,              // deadline
        whitelist_address, // whitelist
        0,                 // Created state
    );

    assert_eq!(
        non_whitelist_auction
            .dutchAuctionParams
            .fillerWhitelistContract,
        Address::ZERO
    );
    assert_eq!(
        whitelist_auction.dutchAuctionParams.fillerWhitelistContract,
        whitelist_address
    );

    // Check if maker is whitelisted
    let whitelist_instance = MappingWhitelistInstance::new(whitelist_address, provider.clone());
    let is_whitelisted = whitelist_instance
        .isWhitelisted(maker.ethereum_address, Bytes::new())
        .call()
        .await
        .unwrap_or(false);

    assert!(is_whitelisted, "Maker should be whitelisted");
}

#[tokio::test]
async fn test_auction_state_change_handling() {
    let maker = MultichainAccount::new(1);
    let hypernode_account = MultichainAccount::new(2);

    let whitelist_address =
        Address::from_str("0x1111111111111111111111111111111111111111").unwrap();

    let auction_created = create_test_auction(
        1,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let mut auction_filled = auction_created.clone();
    // Change to Filled state
    auction_filled.state = 1;

    let (devnet, _funded_sats) = match RiftDevnet::builder()
        .using_bitcoin(true)
        .funded_evm_address(maker.ethereum_address.to_string())
        .data_engine_db_location(DatabaseLocation::InMemory)
        .build()
        .await
    {
        Ok(result) => result,
        Err(e) => {
            println!("Error building devnet: {:?}", e);
            return;
        }
    };

    let evm_ws_rpc = devnet.ethereum.anvil.ws_endpoint_url().to_string();
    let private_key = hex::encode(hypernode_account.secret_bytes);

    let evm_rpc_with_wallet = match create_websocket_wallet_provider(
        &evm_ws_rpc,
        match hex::decode(&private_key) {
            Ok(decoded) => match decoded.try_into() {
                Ok(key) => key,
                Err(_) => {
                    println!("Invalid private key length");
                    return;
                }
            },
            Err(e) => {
                println!("Error decoding key: {:?}", e);
                return;
            }
        },
    )
    .await
    {
        Ok(provider) => Arc::new(provider),
        Err(e) => {
            println!("Error creating websocket provider: {:?}", e);
            return;
        }
    };

    let provider = evm_rpc_with_wallet.clone().erased();

    // Add the maker to the whitelist
    let whitelist_added =
        add_maker_to_whitelist(&provider, maker.ethereum_address, whitelist_address).await;
    assert!(whitelist_added, "Failed to add maker to whitelist");

    // Verify the maker is actually whitelisted
    let whitelist_instance = MappingWhitelistInstance::new(whitelist_address, provider.clone());
    let is_whitelisted = whitelist_instance
        .isWhitelisted(maker.ethereum_address, Bytes::new())
        .call()
        .await
        .unwrap_or(false);

    assert!(is_whitelisted, "Maker should be whitelisted");

    // Test for whitelisted auction too
    let whitelisted_encoded = auction_created.abi_encode();
    let whitelisted_hash = alloy_primitives::keccak256(whitelisted_encoded);
    // Filled state
    let mut auction_filled = auction_created.clone();
    auction_filled.state = 1;
    let filled_encoded = auction_filled.abi_encode();
    let filled_hash = alloy_primitives::keccak256(filled_encoded);

    // The hashes should be different since the state is different
    assert_ne!(
        whitelisted_hash, filled_hash,
        "Whitelisted auction hashes should differ when state changes"
    );

    // Calculate the hash of the auction with original state
    let auction_encoded = auction_created.abi_encode();
    let original_hash = alloy_primitives::keccak256(auction_encoded);

    // Calculate hash for the filled auction
    let modified_encoded = auction_filled.abi_encode();
    let modified_hash = alloy_primitives::keccak256(modified_encoded);

    // The hashes should be different since the state is different
    assert_ne!(
        original_hash, modified_hash,
        "Auction hashes should differ when state changes"
    );
}

#[tokio::test]
async fn test_process_auction_event() {
    let auction = create_test_auction(
        1,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    // Make a log with this auction
    let log = create_log_from_auction(&auction);

    let extracted_auction = extract_auction_from_log(&log).unwrap();
    assert_eq!(
        extracted_auction.index, auction.index,
        "Extracted auction index should match original"
    );
    assert_eq!(
        extracted_auction.state, auction.state,
        "Extracted auction state should match original"
    );
}

// Test auction queue
#[test]
fn test_process_pending_auctions_queue() {
    // Create an auction
    let auction = create_test_auction(
        1,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    // Make pending auctions with different claim times
    let pending1 = PendingAuction {
        auction: auction.clone(),
        claim_at_block: 100,
    };

    let pending2 = PendingAuction {
        auction: auction.clone(),
        claim_at_block: 200,
    };

    let pending3 = PendingAuction {
        auction: auction.clone(),
        claim_at_block: 150,
    };

    // Add to queue
    let mut queue = BinaryHeap::new();
    queue.push(Reverse(pending1));
    queue.push(Reverse(pending2));
    queue.push(Reverse(pending3));

    // Process at block 120
    let current_block = 120;
    let mut to_claim = Vec::new();

    // Get auctions ready to claim
    while let Some(Reverse(pending)) = queue.peek() {
        if pending.claim_at_block <= current_block {
            if let Some(Reverse(auction)) = queue.pop() {
                to_claim.push(auction);
            }
        } else {
            break;
        }
    }

    // Should claim one auction
    assert_eq!(
        to_claim.len(),
        1,
        "Should have 1 auction to claim at block 120"
    );
    assert_eq!(
        to_claim[0].claim_at_block, 100,
        "Auction with claim block 100 should be claimed"
    );

    // Check queue state
    assert_eq!(queue.len(), 2, "Queue should have 2 auctions left");
    assert_eq!(
        queue.peek().unwrap().0.claim_at_block,
        150,
        "Next auction in queue should be for block 150"
    );

    // Process at block 180
    let current_block = 180;
    let mut new_to_claim = Vec::new();

    // Get more auctions
    while let Some(Reverse(pending)) = queue.peek() {
        if pending.claim_at_block <= current_block {
            if let Some(Reverse(auction)) = queue.pop() {
                new_to_claim.push(auction);
            }
        } else {
            break;
        }
    }

    // Should claim another auction
    assert_eq!(
        new_to_claim.len(),
        1,
        "Should have 1 more auction to claim at block 180"
    );
    assert_eq!(
        new_to_claim[0].claim_at_block, 150,
        "Auction with claim block 150 should be claimed"
    );

    // Final queue state
    assert_eq!(queue.len(), 1, "Queue should have 1 auction left");
    assert_eq!(
        queue.peek().unwrap().0.claim_at_block,
        200,
        "Last auction in queue should be for block 200"
    );
}

#[tokio::test]
async fn test_auction_state_changes() {
    // Create test auction in Created state
    let auction_created = create_test_auction(
        1,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    // Set up whitelist address and accounts
    let whitelist_address =
        Address::from_str("0x1111111111111111111111111111111111111111").unwrap();

    let maker = MultichainAccount::new(1);
    let hypernode_account = MultichainAccount::new(2);

    let (devnet, _funded_sats) = match RiftDevnet::builder()
        .using_bitcoin(true)
        .funded_evm_address(maker.ethereum_address.to_string())
        .data_engine_db_location(DatabaseLocation::InMemory)
        .build()
        .await
    {
        Ok(result) => result,
        Err(e) => {
            println!("Error building devnet: {:?}", e);
            return;
        }
    };

    let evm_ws_rpc = devnet.ethereum.anvil.ws_endpoint_url().to_string();
    let private_key = hex::encode(hypernode_account.secret_bytes);

    let evm_rpc_with_wallet = match create_websocket_wallet_provider(
        &evm_ws_rpc,
        match hex::decode(&private_key) {
            Ok(decoded) => match decoded.try_into() {
                Ok(key) => key,
                Err(_) => {
                    println!("Invalid private key length");
                    return;
                }
            },
            Err(e) => {
                println!("Error decoding key: {:?}", e);
                return;
            }
        },
    )
    .await
    {
        Ok(provider) => Arc::new(provider),
        Err(e) => {
            println!("Error creating websocket provider: {:?}", e);
            return;
        }
    };

    let provider = evm_rpc_with_wallet.clone().erased();

    // Add maker to whitelist
    let whitelist_added =
        add_maker_to_whitelist(&provider, maker.ethereum_address, whitelist_address).await;
    assert!(whitelist_added, "Failed to add maker to whitelist");

    // Create a whitelisted auction
    let mut whitelisted_auction_created = auction_created.clone();
    whitelisted_auction_created
        .dutchAuctionParams
        .fillerWhitelistContract = whitelist_address;

    // Make filled
    let mut auction_filled = auction_created.clone();
    auction_filled.state = 1;

    let mut whitelisted_auction_filled = whitelisted_auction_created.clone();
    whitelisted_auction_filled.state = 1;

    // Create logs for all auctions
    let log_created = create_log_from_auction(&auction_created);
    let log_filled = create_log_from_auction(&auction_filled);
    let whitelisted_log_created = create_log_from_auction(&whitelisted_auction_created);
    let whitelisted_log_filled = create_log_from_auction(&whitelisted_auction_filled);

    // Extract auctions from logs
    let extracted_created = extract_auction_from_log(&log_created).unwrap();
    let extracted_filled = extract_auction_from_log(&log_filled).unwrap();
    let extracted_whitelisted_created = extract_auction_from_log(&whitelisted_log_created).unwrap();
    let extracted_whitelisted_filled = extract_auction_from_log(&whitelisted_log_filled).unwrap();

    // Check states are correctly extracted
    assert_eq!(
        extracted_created.state, 0,
        "Created auction should have state 0"
    );
    assert_eq!(
        extracted_filled.state, 1,
        "Filled auction should have state 1"
    );
    assert_eq!(
        extracted_whitelisted_created.state, 0,
        "Created whitelisted auction should have state 0"
    );
    assert_eq!(
        extracted_whitelisted_filled.state, 1,
        "Filled whitelisted auction should have state 1"
    );

    // Check whitelist address is preserved
    assert_eq!(
        extracted_whitelisted_created
            .dutchAuctionParams
            .fillerWhitelistContract,
        whitelist_address,
        "Whitelisted auction should have correct whitelist address"
    );

    // Test claim block calculation
    let current_block = 120;
    let spread_bps = 50;
    let btc_fee_sats = 10;
    let eth_gas_fee_sats = 10;

    // For created state
    let claim_block_created = calculate_optimal_claim_block(
        &extracted_created,
        spread_bps,
        btc_fee_sats,
        eth_gas_fee_sats,
        current_block,
    );

    assert!(
        claim_block_created.is_some(),
        "Should find optimal claim block for created auction"
    );

    let claim_block_filled = calculate_optimal_claim_block(
        &extracted_filled,
        spread_bps,
        btc_fee_sats,
        eth_gas_fee_sats,
        current_block,
    );

    assert_eq!(
        claim_block_created, claim_block_filled,
        "Calculation should be the same regardless of state"
    );

    // For whitelisted auction
    let claim_block_whitelisted = calculate_optimal_claim_block(
        &extracted_whitelisted_created,
        spread_bps,
        btc_fee_sats,
        eth_gas_fee_sats,
        current_block,
    );

    assert!(
        claim_block_whitelisted.is_some(),
        "Should find optimal claim block for whitelisted auction"
    );

    // Check hash calculations
    let created_encoded = auction_created.abi_encode();
    let created_hash = alloy_primitives::keccak256(created_encoded);

    let filled_encoded = auction_filled.abi_encode();
    let filled_hash = alloy_primitives::keccak256(filled_encoded);

    let whitelisted_created_encoded = whitelisted_auction_created.abi_encode();
    let whitelisted_created_hash = alloy_primitives::keccak256(whitelisted_created_encoded);

    // Different states should have different hashes
    assert_ne!(
        created_hash, filled_hash,
        "Auctions with different states should have different hashes"
    );

    // Different whitelist settings should have different hashes
    assert_ne!(
        created_hash, whitelisted_created_hash,
        "Non-whitelisted and whitelisted auctions should have different hashes"
    );

    println!("Auction state tracking test passed successfully");
}

#[test]
fn test_auction_state_change_filter() {
    // Make a queue of pending auctions
    let mut queue = BinaryHeap::new();

    // Create an auction in Created state
    let auction_created = create_test_auction(
        1,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    // Add to the queue
    queue.push(Reverse(PendingAuction {
        auction: auction_created.clone(),
        claim_at_block: 150,
    }));

    // Check queue has one auction
    assert_eq!(queue.len(), 1, "Queue should have one auction");

    // Create the same auction but with Filled state
    let auction_filled = create_test_auction(
        1,             // Same index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        1,             // Filled state
    );

    // Filter queue to remove state-changed auctions
    let mut new_queue = BinaryHeap::new();

    while let Some(Reverse(pending)) = queue.pop() {
        if !(pending.auction.index == auction_filled.index
            && pending.auction.state != auction_filled.state)
        {
            new_queue.push(Reverse(pending));
        }
    }

    // Update queue
    queue = new_queue;

    // Queue should be empty now
    assert_eq!(
        queue.len(),
        0,
        "Queue should be empty after filtering out state-changed auction"
    );
}

#[tokio::test]
async fn test_calculate_optimal_claim_block_comprehensive() {
    // Immediately profitable auction with low spread
    let auction_immediate = create_test_auction(
        1,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let current_block = 110;
    let spread_bps = 10;
    let btc_fee = 5;
    let eth_fee = 5;

    let optimal_block = calculate_optimal_claim_block(
        &auction_immediate,
        spread_bps,
        btc_fee,
        eth_fee,
        current_block,
    );

    assert_eq!(
        optimal_block,
        Some(current_block),
        "Low spread should make auction immediately profitable"
    );

    // Future profitable auction with higher spread
    let auction_future = create_test_auction(
        2,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        500,           // end_btc_out (big drop)
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    let spread_bps = 150;

    let optimal_block =
        calculate_optimal_claim_block(&auction_future, spread_bps, btc_fee, eth_fee, current_block);

    // See if we found a valid solution
    assert!(
        optimal_block.is_some(),
        "Should find a profitable block in the future"
    );

    let opt_block = optimal_block.unwrap();
    assert!(
        opt_block >= current_block,
        "Optimal block should be at or after current block (found: {})",
        opt_block
    );

    assert!(
        opt_block <= 100 + 100, // start_block + decay_blocks
        "Optimal block should be before end of decay period"
    );

    let whitelist_address =
        Address::from_str("0x1111111111111111111111111111111111111111").unwrap();

    let auction_whitelist = create_test_auction(
        4,                 // index
        10000,             // deposit_amount
        100,               // start_block
        1000,              // start_btc_out
        900,               // end_btc_out
        100,               // decay_blocks
        1000,              // deadline
        whitelist_address, // whitelist
        0,                 // Created state
    );

    let optimal_block =
        calculate_optimal_claim_block(&auction_whitelist, 10, btc_fee, eth_fee, current_block);

    assert_eq!(
        optimal_block,
        Some(current_block),
        "Whitelist should not affect profitability calculation"
    );
}

#[tokio::test]
async fn test_auction_log_extraction() {
    // Create a test auction
    let auction = create_test_auction(
        1,             // index
        10000,         // deposit_amount
        100,           // start_block
        1000,          // start_btc_out
        900,           // end_btc_out
        100,           // decay_blocks
        1000,          // deadline
        Address::ZERO, // whitelist
        0,             // Created state
    );

    // Create a log for the auction
    let log = create_log_from_auction(&auction);

    // Extract the auction from the log
    let extracted_auction = extract_auction_from_log(&log).unwrap();

    // Check that extracted auction matches original
    assert_eq!(
        extracted_auction.index, auction.index,
        "Extracted auction index should match original"
    );

    assert_eq!(
        extracted_auction.depositAmount, auction.depositAmount,
        "Extracted deposit amount should match original"
    );

    assert_eq!(
        extracted_auction.dutchAuctionParams.startBtcOut, auction.dutchAuctionParams.startBtcOut,
        "Extracted start BTC out should match original"
    );

    assert_eq!(
        extracted_auction.dutchAuctionParams.endBtcOut, auction.dutchAuctionParams.endBtcOut,
        "Extracted end BTC out should match original"
    );

    assert_eq!(
        extracted_auction.state, auction.state,
        "Extracted state should match original"
    );
}

#[tokio::test]
async fn test_whitelist_verification() {
    let maker = MultichainAccount::new(1);
    let hypernode_account = MultichainAccount::new(2);

    let whitelist_address =
        Address::from_str("0x1111111111111111111111111111111111111111").unwrap();

    let (devnet, _funded_sats) = match RiftDevnet::builder()
        .using_bitcoin(true)
        .funded_evm_address(maker.ethereum_address.to_string())
        .data_engine_db_location(DatabaseLocation::InMemory)
        .build()
        .await
    {
        Ok(result) => result,
        Err(e) => {
            println!("Error building devnet: {:?}", e);
            return;
        }
    };

    let evm_ws_rpc = devnet.ethereum.anvil.ws_endpoint_url().to_string();
    let private_key = hex::encode(hypernode_account.secret_bytes);

    let evm_rpc_with_wallet = match create_websocket_wallet_provider(
        &evm_ws_rpc,
        match hex::decode(&private_key) {
            Ok(decoded) => match decoded.try_into() {
                Ok(key) => key,
                Err(_) => {
                    println!("Invalid private key length");
                    return;
                }
            },
            Err(e) => {
                println!("Error decoding key: {:?}", e);
                return;
            }
        },
    )
    .await
    {
        Ok(provider) => Arc::new(provider),
        Err(e) => {
            println!("Error creating websocket provider: {:?}", e);
            return;
        }
    };

    let provider = evm_rpc_with_wallet.clone().erased();

    // Add maker to whitelist
    let whitelist_added =
        add_maker_to_whitelist(&provider, maker.ethereum_address, whitelist_address).await;
    assert!(whitelist_added, "Failed to add maker to whitelist");

    let auction = create_test_auction(
        1,                 // index
        10000,             // deposit_amount
        100,               // start_block
        1000,              // start_btc_out
        900,               // end_btc_out
        100,               // decay_blocks
        1000,              // deadline
        whitelist_address, // whitelist
        0,                 // Created state
    );

    // Make a config with the maker's address
    let config = AuctionClaimerConfig {
        auction_house_address: Address::ZERO,
        market_maker_address: maker.ethereum_address,
        spread_bps: 10,
        btc_fee_sats: 5,
        eth_gas_fee_sats: 5,
        max_batch_size: 10,
        evm_ws_rpc: evm_ws_rpc.clone(),
        light_client_address: None,
    };

    // Check maker is whitelisted
    let whitelist_instance = MappingWhitelistInstance::new(whitelist_address, provider.clone());
    let is_whitelisted = whitelist_instance
        .isWhitelisted(config.market_maker_address, Bytes::new())
        .call()
        .await
        .unwrap_or(false);

    assert!(is_whitelisted, "Maker should be whitelisted");

    // Calculate optimal claim block
    let result = calculate_optimal_claim_block(
        &auction,
        config.spread_bps,
        config.btc_fee_sats,
        config.eth_gas_fee_sats,
        120,
    );
    assert_eq!(
        result,
        Some(120),
        "Whitelisted auction should be immediately profitable for maker in whitelist"
    );
}

#[tokio::test]
async fn test_auction_claimer_end_to_end() {
    // Setup test accounts
    let market_maker = MultichainAccount::new(1);
    let filler_account = MultichainAccount::new(2);
    let auction_owner = MultichainAccount::new(3);

    // Set up devnet with Bitcoin enabled
    let (devnet, _funded_sats) = match RiftDevnet::builder()
        .using_bitcoin(true)
        .funded_evm_address(market_maker.ethereum_address.to_string())
        .funded_evm_address(filler_account.ethereum_address.to_string())
        .funded_evm_address(auction_owner.ethereum_address.to_string())
        .data_engine_db_location(DatabaseLocation::InMemory)
        .build()
        .await
    {
        Ok(result) => result,
        Err(e) => {
            panic!("Failed to build devnet: {:?}", e);
        }
    };

    // Get WebSocket RPC URL from devnet
    let evm_ws_rpc = devnet.ethereum.anvil.ws_endpoint_url().to_string();
    info!("WebSocket RPC URL: {}", evm_ws_rpc);

    // Create provider with wallet for auction owner
    let private_key_owner = hex::encode(auction_owner.secret_bytes);
    let provider_owner = match create_websocket_wallet_provider(
        &evm_ws_rpc,
        match hex::decode(&private_key_owner) {
            Ok(decoded) => match decoded.try_into() {
                Ok(key) => key,
                Err(_) => panic!("Invalid private key length"),
            },
            Err(e) => panic!("Error decoding key: {:?}", e),
        },
    )
    .await
    {
        Ok(provider) => Arc::new(provider),
        Err(e) => panic!("Error creating websocket provider: {:?}", e),
    };

    // Create provider with wallet for filler
    let private_key_filler = hex::encode(filler_account.secret_bytes);
    let provider_filler = match create_websocket_wallet_provider(
        &evm_ws_rpc,
        match hex::decode(&private_key_filler) {
            Ok(decoded) => match decoded.try_into() {
                Ok(key) => key,
                Err(_) => panic!("Invalid private key length"),
            },
            Err(e) => panic!("Error decoding key: {:?}", e),
        },
    )
    .await
    {
        Ok(provider) => Arc::new(provider),
        Err(e) => panic!("Error creating websocket provider: {:?}", e),
    };

    let auction_house_address =
        Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
    let exchange_address = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
    let whitelist_address =
        Address::from_str("0x3333333333333333333333333333333333333333").unwrap();
    let light_client_address =
        Address::from_str("0x4444444444444444444444444444444444444444").unwrap();

    // Create test auctions with different parameters
    let current_block = provider_owner.get_block_number().await.unwrap_or(0);

    // Setup whitelist for market maker
    let whitelist_added = add_maker_to_whitelist(
        &provider_owner.erased(),
        market_maker.ethereum_address,
        whitelist_address,
    )
    .await;
    assert!(whitelist_added, "Failed to add market maker to whitelist");

    // Create a non-whitelisted auction - immediately profitable
    let auction1 = create_test_auction(
        1,                    // index
        10000,                // deposit_amount
        current_block,        // start_block
        1000,                 // start_btc_out
        900,                  // end_btc_out
        100,                  // decay_blocks
        current_block + 1000, // deadline
        Address::ZERO,        // whitelist
        0,                    // Created state
    );

    // Create a whitelisted auction - profitable in future
    let auction2 = create_test_auction(
        2,                    // index
        10000,                // deposit_amount
        current_block,        // start_block
        1200,                 // start_btc_out - higher than auction1
        800,                  // end_btc_out
        100,                  // decay_blocks
        current_block + 1000, // deadline
        whitelist_address,    // Using whitelist
        0,                    // Created state
    );

    // Create a never profitable auction
    let auction3 = create_test_auction(
        3,                    // index
        800,                  // deposit_amount too low
        current_block,        // start_block
        1000,                 // start_btc_out
        900,                  // end_btc_out
        100,                  // decay_blocks
        current_block + 1000, // deadline
        Address::ZERO,        // whitelist
        0,                    // Created state
    );

    // Setup AuctionClaimer configuration
    let auction_claimer_config = AuctionClaimerConfig {
        auction_house_address,
        market_maker_address: market_maker.ethereum_address,
        spread_bps: 50,
        btc_fee_sats: 10,
        eth_gas_fee_sats: 10,
        max_batch_size: 2,
        evm_ws_rpc: evm_ws_rpc.clone(),
        light_client_address: Some(light_client_address),
    };

    // Create the auction claimer
    let auction_claimer = AuctionClaimer::new(
        evm_ws_rpc.clone(),
        private_key_filler.clone(),
        auction_claimer_config.clone(),
        None, //TODO: Add contract data engine
    );

    // Create a channel for auction events
    let (auction_tx, mut auction_rx) = mpsc::channel(100);
    let pending_auctions = Arc::new(Mutex::new(BinaryHeap::new()));

    let provider = provider_filler.erased();

    // Process auction events
    info!("Processing auction events...");
    for auction in [auction1.clone(), auction2.clone(), auction3.clone()] {
        let log = create_log_from_auction(&auction);

        // Process the auction event
        AuctionClaimer::process_auction_event(
            provider.clone(),
            pending_auctions.clone(),
            auction_claimer_config.clone(),
            log,
            auction_tx.clone(),
        )
        .await
        .expect("Failed to process auction event");
    }

    // Verify pending auctions queue contains the right auctions
    let queue = pending_auctions.lock().await;
    assert!(
        queue.len() > 0,
        "Pending auctions queue should not be empty"
    );

    // Verify auction1 is in the queue
    let contains_auction1 = queue
        .iter()
        .any(|Reverse(pending)| pending.auction.index == auction1.index);
    assert!(contains_auction1, "Auction1 should be in the pending queue");

    // Auction3 should not be in the queue cuz it's never profitable
    let contains_auction3 = queue
        .iter()
        .any(|Reverse(pending)| pending.auction.index == auction3.index);
    assert!(
        !contains_auction3,
        "Auction3 should not be in the pending queue (never profitable)"
    );

    drop(queue);

    // Move up blocks to trigger auction processing
    let next_block = current_block + 10;
    info!("Processing pending auctions at block {}...", next_block);

    // Process pending auctions that should be claimed
    AuctionClaimer::process_pending_auctions(
        provider.clone(),
        pending_auctions.clone(),
        next_block,
        auction_claimer_config.max_batch_size,
        auction_tx.clone(),
        auction_claimer_config.clone(),
    )
    .await
    .expect("Failed to process pending auctions");

    // Verify that auction1 was sent for claiming
    let mut auctions_to_claim = Vec::new();

    let has_auction_to_claim = tokio::select! {
        Some((auction, claim_block)) = auction_rx.recv() => {
            auctions_to_claim.push((auction, claim_block));
            true
        }
    };

    assert!(
        has_auction_to_claim,
        "Should have at least one auction to claim"
    );

    // Verify that auction1 was sent for claiming
    let contains_auction1 = auctions_to_claim
        .iter()
        .any(|(auction, _)| auction.index == auction1.index);
    assert!(
        contains_auction1,
        "Auction1 should be selected for claiming"
    );

    // Create a state change for auction2 (change to Filled state)
    let mut auction2_filled = auction2.clone();
    auction2_filled.state = 1;

    // Create a log for the updated auction
    let log_filled = create_log_from_auction(&auction2_filled);

    // Process the state change event
    AuctionClaimer::process_auction_event(
        provider.clone(),
        pending_auctions.clone(),
        auction_claimer_config.clone(),
        log_filled,
        auction_tx.clone(),
    )
    .await
    .expect("Failed to process auction state change event");

    // Verify auction2 was removed from the queue
    let queue = pending_auctions.lock().await;
    let contains_auction2 = queue
        .iter()
        .any(|Reverse(pending)| pending.auction.index == auction2.index);
    assert!(
        !contains_auction2,
        "Auction2 should be removed after state change"
    );

    // Verify the verify_auction_state method works correctly
    let is_valid =
        AuctionClaimer::verify_auction_state(provider.clone(), &auction_claimer_config, &auction1)
            .await
            .expect("Failed to verify auction state");

    assert!(is_valid, "Auction1 should still be valid");
}
