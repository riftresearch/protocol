use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
};
use alloy::providers::{Identity, Provider, RootProvider};
use rand::seq::SliceRandom;
use serde_json::Value;
use std::time::Duration;
use tokio::time::timeout;

use anyhow::Result;

use crate::quote::FetchEthPrice;

pub type RpcProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

pub const MAINNET_CHAIN_ID: u64 = 1;
pub const CHUNK_SIZE: usize = 5;
pub const RPC_TIMEOUT: Duration = Duration::from_millis(250);

pub struct ChainData {
    pub name: String,
    pub gas_per_unit_wei: u128,
    pub eth_price: Option<f64>,
}

pub fn get_eth_cost_for_gas_limit(gas_price_in_wei: u128, gas_limit: u64) -> (f64, f64) {
    let gas_fee_gwei = gas_price_in_wei as f64 / 1_000_000_000.0;
    let gas_cost_wei = (gas_price_in_wei * gas_limit as u128) as f64;
    let gas_cost_eth = gas_cost_wei / 10f64.powi(18);
    (gas_cost_eth, gas_fee_gwei)
}
