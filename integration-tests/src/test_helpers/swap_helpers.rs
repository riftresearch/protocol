use alloy::providers::ext::AnvilApi;
use rift_indexer::models::{OTCSwap, SwapStatus};
use std::time::Duration;

use super::fixtures::TestFixture;

/// Wait for a swap to reach a specific status
pub async fn wait_for_swap_status(
    fixture: &TestFixture,
    order_index: u64,
    expected_status: SwapStatus,
    timeout: Duration,
) -> OTCSwap {
    let start = std::time::Instant::now();
    
    loop {
        if start.elapsed() > timeout {
            panic!(
                "Timeout waiting for swap {} to reach status {:?}",
                order_index, expected_status
            );
        }
        
        match fixture
            .devnet
            .rift_indexer
            .get_otc_swap_by_order_index(order_index)
            .await
            .unwrap()
        {
            Some(swap) => {
                println!("Swap {} status: {:?}", order_index, swap.swap_status());
                if swap.swap_status() == expected_status {
                    return swap;
                }
            }
            None => {
                println!("Swap {} not found yet", order_index);
            }
        }
        
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Wait for swap to enter challenge period
pub async fn wait_for_challenge_period(
    fixture: &TestFixture,
    order_index: u64,
) -> OTCSwap {
    wait_for_swap_status(
        fixture,
        order_index,
        SwapStatus::ChallengePeriod,
        Duration::from_secs(60),
    )
    .await
}

/// Wait for swap to complete
pub async fn wait_for_completion(
    fixture: &TestFixture,
    order_index: u64,
) -> OTCSwap {
    wait_for_swap_status(
        fixture,
        order_index,
        SwapStatus::Completed,
        Duration::from_secs(60),
    )
    .await
}

/// Complete a swap by warping time past the challenge period
pub async fn complete_swap_after_challenge(
    fixture: &TestFixture,
    swap: &OTCSwap,
) {
    let unlock_timestamp = swap
        .payments
        .first()
        .unwrap()
        .payment
        .challengeExpiryTimestamp
        + 1;
    
    // Warp time on Ethereum
    fixture
        .devnet
        .ethereum
        .funded_provider
        .anvil_set_time(unlock_timestamp)
        .await
        .unwrap();
    
    // Mine a block to trigger the time change
    fixture
        .devnet
        .ethereum
        .funded_provider
        .anvil_mine(Some(1), None)
        .await
        .unwrap();
}

/// Helper to run a complete swap flow
pub async fn run_complete_swap_flow(
    fixture: &TestFixture,
    order_index: u64,
) -> OTCSwap {
    // Wait for challenge period
    let swap = wait_for_challenge_period(fixture, order_index).await;
    
    // Complete the swap
    complete_swap_after_challenge(fixture, &swap).await;
    
    // Wait for completion
    wait_for_completion(fixture, order_index).await
}

/// Check if a swap exists
pub async fn swap_exists(fixture: &TestFixture, order_index: u64) -> bool {
    fixture
        .devnet
        .rift_indexer
        .get_otc_swap_by_order_index(order_index)
        .await
        .unwrap()
        .is_some()
}