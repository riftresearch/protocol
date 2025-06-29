use devnet::RiftDevnet;

#[tokio::test]
async fn test_devnet_boots() {
    RiftDevnet::builder()
        .using_esplora(true)
        .build()
        .await
        .unwrap();
}
