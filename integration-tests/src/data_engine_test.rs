use crate::test_utils::setup_test_tracing;

use bitcoin_light_client_core::{
    leaves::{create_new_leaves, get_genesis_leaf, BlockLeaf},
    light_client::{calculate_cumulative_work, Header},
};
use data_engine::engine::ContractDataEngine;
use rift_sdk::DatabaseLocation;
use test_data_utils::TEST_HEADERS;

fn get_test_data() -> Vec<BlockLeaf> {
    let headers = TEST_HEADERS
        .clone()
        .iter()
        .map(|(_, h)| Header::new(h))
        .collect::<Vec<_>>();
    let (cumulative_chainworks, _) = calculate_cumulative_work(crypto_bigint::U256::ZERO, &headers);
    create_new_leaves(&get_genesis_leaf(), &headers, &cumulative_chainworks)
}

// TODO: Compared with test_data_engine_in_memory_db, it's obvious* the file based DB is much slower
// We need to figure out how to speed up the underyling sqlite operations, perhap through modifying the
// MMR library to support sqlite batching or by improving the underlying SQL queries.
// Benchmark difference:
// * cargo test --release test_data_engine_in_memory_db -- --nocapture
// * vs
// * cargo test --release test_data_engine_file_db -- --nocapture
#[tokio::test]
async fn test_data_engine_file_db() {
    setup_test_tracing();
    // create a temp directory
    let temp_dir = tempfile::tempdir().unwrap();
    let dir_str = temp_dir.path().to_str().unwrap().to_string();

    ContractDataEngine::seed(&DatabaseLocation::Directory(dir_str), get_test_data())
        .await
        .unwrap();
}

#[tokio::test]
async fn test_data_engine_in_memory_db() {
    setup_test_tracing();
    ContractDataEngine::seed(&DatabaseLocation::InMemory, get_test_data())
        .await
        .unwrap();
}
