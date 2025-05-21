/// Fetch ETH->USD price from Uniswap v3 on Ethereum mainnet
use crate::chains::RpcProvider;
use crate::chains::{CHAIN_ID_TO_RPCS_MAP, CHUNK_SIZE, RPC_TIMEOUT};
use alloy::{
    primitives::{address, Address, U160, U256},
    providers::{Provider, ProviderBuilder},
    sol,
};
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::timeout;

pub const UNISWAP_V3_USDC_ETH_POOL_ADDRESS: Address =
    address!("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640");
pub const WBTC_DECIMALS: i32 = 8;
pub const WETH_DECIMALS: i32 = 18;

lazy_static::lazy_static! {
    static ref CHAIN_ID_TO_WETH_WBTC_POOL_MAP: HashMap<u64, Address> = {
        let mut m = HashMap::new();
        m.insert(1, address!("15aA01580ae866f9FF4DBe45E06e307941d90C7b")); // ETH Mainnet
        // insert other chain ids and their WETH/WBTC pool addresses here
        m
    };
}

fn get_weth_wbtc_pool_for_chain(chain_id: u64) -> Option<Address> {
    CHAIN_ID_TO_WETH_WBTC_POOL_MAP.get(&chain_id).copied()
}

sol!(
    #[sol(rpc)]
    IUniswapV3PoolState,
    r#"[{
        "inputs": [],
        "name": "slot0",
        "outputs": [
        {
            "internalType": "uint160",
            "name": "sqrtPriceX96",
            "type": "uint160"
        },
        {
            "internalType": "int24",
            "name": "tick",
            "type": "int24"
        },
        {
            "internalType": "uint16",
            "name": "observationIndex",
            "type": "uint16"
        },
        {
            "internalType": "uint16",
            "name": "observationCardinality",
            "type": "uint16"
        },
        {
            "internalType": "uint16",
            "name": "observationCardinalityNext",
            "type": "uint16"
        },
        {
            "internalType": "uint8",
            "name": "feeProtocol",
            "type": "uint8"
        },
        {
            "internalType": "bool",
            "name": "unlocked",
            "type": "bool"
        }
        ],
        "stateMutability": "view",
        "type": "function"
  }]"#
);

#[async_trait::async_trait]
pub trait FetchEthPrice {
    async fn fetch_eth_price(&self) -> anyhow::Result<f64>;
}

#[derive(Debug, Clone, Copy)]
pub struct ConversionRates {
    pub wbtc_per_eth: f64,
    pub eth_per_wbtc: f64,
}

#[async_trait::async_trait]
impl FetchEthPrice for RpcProvider {
    async fn fetch_eth_price(&self) -> anyhow::Result<f64> {
        let pool = IUniswapV3PoolState::new(UNISWAP_V3_USDC_ETH_POOL_ADDRESS, self);

        let slot0 = pool.slot0().call().await?;

        let sqrt_price_float = q64_96_to_float(slot0.sqrtPriceX96);
        let price_float = sqrt_price_float * sqrt_price_float;
        let price_per_eth = 10f64.powi(12) / price_float;
        Ok(price_per_eth)
    }
}

pub async fn fetch_weth_wbtc_conversion_rates(chain_id: u64) -> anyhow::Result<ConversionRates> {
    let chain_id_str = chain_id.to_string();

    let pool_address = get_weth_wbtc_pool_for_chain(chain_id).ok_or_else(|| {
        anyhow::anyhow!(
            "WETH/WBTC pool address not configured for chain_id: {}",
            chain_id
        )
    })?;

    let mut rpcs = CHAIN_ID_TO_RPCS_MAP[&chain_id_str]["rpcs"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No RPCs found for chain id: {}", chain_id_str))?
        .to_owned();

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

        let results = futures::future::join_all(rpc_urls.iter().map(|url| {
            let pool_address_clone = pool_address;
            async move {
                let provider = ProviderBuilder::new().on_http(url.clone());

                let pool = IUniswapV3PoolState::new(pool_address_clone, &provider);

                match timeout(RPC_TIMEOUT, pool.slot0().call()).await {
                    Ok(Ok(slot0_data)) => {
                        let p_sqrt = q64_96_to_float(slot0_data.sqrtPriceX96);
                        let price_t1_in_t0_unadjusted = p_sqrt * p_sqrt;

                        let scaling_exponent_wbtc_per_weth = WETH_DECIMALS - WBTC_DECIMALS;
                        let scaling_factor_wbtc_per_weth =
                            10f64.powi(scaling_exponent_wbtc_per_weth);

                        let actual_wbtc_for_1_weth =
                            price_t1_in_t0_unadjusted * scaling_factor_wbtc_per_weth;
                        let actual_weth_for_1_wbtc = 1.0 / actual_wbtc_for_1_weth;

                        Some(ConversionRates {
                            wbtc_per_eth: actual_wbtc_for_1_weth,
                            eth_per_wbtc: actual_weth_for_1_wbtc,
                        })
                    }
                    Ok(Err(_)) | Err(_) => None,
                }
            }
        }))
        .await;

        for result in results {
            if let Some(rates) = result {
                return Ok(rates);
            }
        }
    }

    Err(anyhow::anyhow!(
        "No valid provider found for WETH/WBTC rates on chain_id: {} within timeout period",
        chain_id_str
    ))
}

pub fn q64_96_to_float(num: U160) -> f64 {
    let limbs = num.into_limbs();
    let lo = limbs[0] as f64; // bits 0..64
    let mid = limbs[1] as f64 * 2f64.powi(64); // bits 64..128
    let hi = limbs[2] as f64 * 2f64.powi(128); // bits 128..160 (top 32 bits used)

    let full = lo + mid + hi;
    full / 2f64.powi(96)
}
