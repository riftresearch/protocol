use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
};
use alloy::providers::{Identity, Provider, ProviderBuilder, RootProvider};
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

const CHAIN_ID_TO_NAME: &str = include_str!("chainIdToName.json");
const CHAIN_ID_TO_RPCS: &str = include_str!("chainIdToRpcs.json");

lazy_static::lazy_static! {
    pub static ref CHAIN_ID_TO_NAME_MAP: Value = serde_json::from_str(CHAIN_ID_TO_NAME).unwrap();
    pub static ref CHAIN_ID_TO_RPCS_MAP: Value = serde_json::from_str(CHAIN_ID_TO_RPCS).unwrap();
}

pub struct ChainData {
    pub name: String,
    pub gas_per_unit_wei: u128,
    pub eth_price: Option<f64>,
}

pub async fn get_gas_data(chain_id: u64, fetch_eth_price: bool) -> Result<ChainData> {
    let chain_id_str = chain_id.to_string();
    const RPC_TIMEOUT: Duration = Duration::from_millis(250);

    // Rpc entries could be a string or an object with a url key
    let mut rpcs = CHAIN_ID_TO_RPCS_MAP[&chain_id_str]["rpcs"]
        .as_array()
        .expect("No RPCs found for chain id")
        .to_owned();

    // randomize the rpcs
    let mut rng = rand::rng();
    rpcs.shuffle(&mut rng);

    for rpc_window in rpcs.chunks(CHUNK_SIZE) {
        let rpc_urls: Vec<reqwest::Url> = rpc_window
            .iter()
            .map(|rpc| {
                rpc["url"]
                    .as_str()
                    .unwrap_or_else(|| {
                        rpc.as_str().expect(
                            "Entry didn't have a defined URL (neither as string nor object)",
                        )
                    })
                    .parse::<reqwest::Url>()
                    .expect("Invalid URL")
            })
            .collect();

        let results = futures::future::join_all(rpc_urls.iter().map(|url| async {
            let provider = ProviderBuilder::new().on_http(url.clone());

            let gas_price = match timeout(RPC_TIMEOUT, provider.get_gas_price()).await {
                Ok(Ok(price)) => Some(price),
                Ok(Err(_)) | Err(_) => None,
            };

            let eth_price = if fetch_eth_price {
                match timeout(RPC_TIMEOUT, provider.fetch_eth_price()).await {
                    Ok(Ok(price)) => Some(price),
                    Ok(Err(_)) | Err(_) => None,
                }
            } else {
                None
            };

            if let Some(gas_price) = gas_price {
                Some(ChainData {
                    name: CHAIN_ID_TO_NAME_MAP
                        .get(&chain_id_str)
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .unwrap_or_else(|| format!("Unknown Chain: {}", chain_id_str)),
                    gas_per_unit_wei: gas_price,
                    eth_price,
                })
            } else {
                None
            }
        }))
        .await;

        for result in results {
            match result {
                Some(chain_data) => {
                    return Ok(chain_data);
                }
                _ => {
                    continue;
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "No valid provider found for chain id: {} within timeout period",
        chain_id_str
    ))
}

pub fn get_eth_cost_for_gas_limit(gas_price_in_wei: u128, gas_limit: u64) -> (f64, f64) {
    let gas_fee_gwei = gas_price_in_wei as f64 / 1_000_000_000.0;
    let gas_cost_wei = (gas_price_in_wei * gas_limit as u128) as f64;
    let gas_cost_eth = gas_cost_wei / 10f64.powi(18);
    (gas_cost_eth, gas_fee_gwei)
}

// these are the chain ids that are *NOT* ethereum mainnet
// returns a tuple of the ethereum mainnet chain metadata and a list of chain metadata
pub async fn fetch_gas_data(alt_chain_ids: &[u64]) -> anyhow::Result<(ChainData, Vec<ChainData>)> {
    let mainnet_future = get_gas_data(MAINNET_CHAIN_ID, true);
    let alt_chain_futures: Vec<_> = alt_chain_ids
        .iter()
        .map(|chain_id| get_gas_data(*chain_id, false))
        .collect();

    let (mainnet_chain, alt_chains) =
        tokio::join!(mainnet_future, futures::future::join_all(alt_chain_futures));

    let chains: Vec<ChainData> = alt_chains.into_iter().collect::<Result<Vec<_>, _>>()?;
    Ok((mainnet_chain?, chains))
}
