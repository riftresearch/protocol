use alloy::{primitives::Address, providers::Provider, pubsub::PubSubFrontend};
use std::sync::Arc;

struct SwapWatchtower {
    evm_rpc: Arc<dyn Provider<PubSubFrontend>>,
    rift_exchange_address: Address,
}

impl SwapWatchtower {
    pub fn new(evm_rpc: Arc<dyn Provider<PubSubFrontend>>, rift_exchange_address: Address) -> Self {
        Self {
            evm_rpc,
            rift_exchange_address,
        }
    }
}
