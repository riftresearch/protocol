use crate::test_helpers::{
    bitcoin_helpers::pay_for_order_as_taker,
    fixtures::{TestConfig, TestFixture},
    hypernode_helpers::spawn_and_wait_for_hypernode,
    order_helpers::{create_default_order, OrderBuilder},
    swap_helpers::run_complete_swap_flow,
};

#[tokio::test]
async fn test_hypernode_simple_swap() {
    // Setup test environment
    let fixture = TestFixture::new().await;

    // Spawn hypernode to process the payment
    let hypernode_handle = spawn_and_wait_for_hypernode(&fixture).await;

    // Create an order
    let order = create_default_order(&fixture).await;
    println!("Created order with index: {}", order.index);

    // Pay for the order as taker
    pay_for_order_as_taker(&fixture, &order).await;

    // Wait for swap to complete
    run_complete_swap_flow(&fixture, order.index.to::<u64>()).await;

    println!("Swap completed successfully!");

    // Cleanup
    hypernode_handle.abort();
}

#[tokio::test]
async fn test_hypernode_multiple_swaps() {
    // Setup with multiple makers
    let config = TestConfig {
        auto_mine_ethereum: true,
        num_additional_makers: 1,
    };
    let fixture = TestFixture::with_config(config).await;

    // Spawn hypernode first
    let hypernode_handle = spawn_and_wait_for_hypernode(&fixture).await;

    // First swap with default maker
    let order1 = create_default_order(&fixture).await;
    pay_for_order_as_taker(&fixture, &order1).await;
    run_complete_swap_flow(&fixture, order1.index.to::<u64>()).await;
    println!("First swap completed!");

    // Second swap with additional maker
    let order2 = OrderBuilder::new()
        .with_salt([0x55; 32])
        .create_as_maker(&fixture, 1)
        .await;
    pay_for_order_as_taker(&fixture, &order2).await;
    run_complete_swap_flow(&fixture, order2.index.to::<u64>()).await;
    println!("Second swap completed!");

    // Cleanup
    hypernode_handle.abort();
}
