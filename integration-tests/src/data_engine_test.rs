use super::*;
use bitcoin_light_client_core::leaves::BlockLeaf;
use data_engine::engine::ContractDataEngine;
use devnet::{EthDevnet, RiftDevnet};
use rift_sdk::DatabaseLocation;
use tokio::{signal, task::JoinSet};
use tokio_util::task::TaskTracker;

#[tokio::test]
async fn test_data_engine_with_real_file() {
    // create a temp directory
    let temp_dir = tempfile::tempdir().unwrap();
    // we only need a devnet so the provider is real, not actually used so pass in dummy values
    let (eth_devnet, deploy_block_number) =
        EthDevnet::setup([0; 32], [0; 32], BlockLeaf::default(), None, false)
            .await
            .unwrap();
    /*
    database_location: &DatabaseLocation,
    provider: Arc<dyn Provider<PubSubFrontend>>,
    rift_exchange_address: String,
    deploy_block_number: u64,
    checkpoint_leaves: Vec<BlockLeaf>,
    */
    let mut join_set = JoinSet::new();
    let data_engine = ContractDataEngine::start(
        &DatabaseLocation::Directory(temp_dir.path().to_str().unwrap().to_string()),
        eth_devnet.funded_provider,
        *eth_devnet.rift_exchange_contract.address(),
        deploy_block_number,
        vec![],
        &mut join_set,
    )
    .await
    .unwrap();
}
