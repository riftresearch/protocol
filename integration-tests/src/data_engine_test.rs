mod tests {
    use super::*;
    use data_engine::run_data_engine;
    use data_engine::setup_database;
    use devnet::core::RiftDevnet;

    #[tokio::test]
    async fn test_data_engine() {
        /* 
        let devnet = RiftDevnet::setup(None).await.unwrap();
        let pool = setup_database(true).await.unwrap();
        let ws_endpoint_url = devnet.anvil_instance.ws_endpoint_url();
        let exchange_address = devnet.rift_exchange_contract.address().to_string();
        let data_engine_task =
            run_data_engine(ws_endpoint_url.as_ref(), exchange_address.as_ref(), &pool);
            */
    }
}
