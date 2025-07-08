#![allow(dead_code)]

#[cfg(test)]
mod auction_claimer_test;
#[cfg(test)]
mod bitcoin_data_engine_test;
#[cfg(test)]
mod btc_txn_broadcaster_test;
#[cfg(test)]
mod data_engine_test;
#[cfg(test)]
mod devnet_test;
#[cfg(test)]
mod fork_watchtower_test;
#[cfg(test)]
mod hypernode_test;
#[cfg(test)]
mod light_client_update_watchtower_test;
#[cfg(test)]
mod market_maker_hypernode_e2e_test;
#[cfg(test)]
mod dual_hypernode_market_maker_test;
#[cfg(test)]
mod quote_test;
#[cfg(test)]
mod test_helpers;
#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod txn_broadcast_test;

use ctor::ctor;
use tracing_subscriber::EnvFilter;

#[ctor]
fn init_test_tracing() {
    let has_nocapture = std::env::args().any(|arg| arg == "--nocapture" || arg == "--show-output");
    if has_nocapture {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .try_init()
            .ok();
    }
}
