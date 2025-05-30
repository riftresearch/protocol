/// Fetch ETH->USD price from Uniswap v3 on Ethereum mainnet
use crate::chains::RpcProvider;
use crate::chains::{CHUNK_SIZE, RPC_TIMEOUT};
use alloy::providers::DynProvider;
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

#[derive(Debug, Clone, Copy)]
struct ChainAddresses {
    weth_address: Address,
    weth_cbbtc_pool_address: Address,
}

lazy_static::lazy_static! {
    static ref CHAIN_ADDRESSES: HashMap<u64, ChainAddresses> = {
        let mut m = HashMap::new();
        m.insert(1, ChainAddresses {
            weth_address: address!("0xC02aaA39b223FE8D0A0E5C4F27eAD9083C756Cc2"),
            weth_cbbtc_pool_address: address!("0x15aA01580ae866f9FF4DBe45E06e307941d90C7b"),
        });
        m.insert(8453, ChainAddresses {
            weth_address: address!("0x4200000000000000000000000000000000000006"),
            weth_cbbtc_pool_address: address!("0x8c7080564B5A792A33Ef2FD473fbA6364d5495e5"),
        });
        m
    };
}

fn get_weth_address(chain_id: u64) -> Option<Address> {
    CHAIN_ADDRESSES
        .get(&chain_id)
        .map(|addrs| addrs.weth_address)
}

fn get_weth_cbbtc_pool_address(chain_id: u64) -> Option<Address> {
    CHAIN_ADDRESSES
        .get(&chain_id)
        .map(|addrs| addrs.weth_cbbtc_pool_address)
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

sol!(
    #[sol(rpc)]
    IUniswapV3PoolImmutables,
    r#"[
        {
            "inputs": [],
            "name": "token0",
            "outputs": [{"internalType": "address", "name": "", "type": "address"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "token1",
            "outputs": [{"internalType": "address", "name": "", "type": "address"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]"#
);

#[async_trait::async_trait]
pub trait FetchEthPrice {
    async fn fetch_eth_price(&self) -> anyhow::Result<f64>;
}

#[derive(Debug, Clone, Copy)]
pub struct ConversionRates {
    pub cbbtc_per_eth: f64,
    pub eth_per_cbbtc: f64,
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

pub async fn fetch_weth_cbbtc_conversion_rates(
    provider: DynProvider,
    chain_id: u64,
) -> anyhow::Result<ConversionRates> {
    let pool_address = get_weth_cbbtc_pool_address(chain_id).ok_or_else(|| {
        anyhow::anyhow!(
            "WETH/cbBTC pool info not configured for chain_id: {}",
            chain_id
        )
    })?;

    let weth_address = get_weth_address(chain_id)
        .ok_or_else(|| anyhow::anyhow!("WETH address not configured for chain_id: {}", chain_id))?;

    let pool_address_clone = pool_address;
    let weth_address_clone = weth_address;

    let pool = IUniswapV3PoolState::new(pool_address_clone, &provider);
    let pool_immut = IUniswapV3PoolImmutables::new(pool_address_clone, &provider);

    let rates = match timeout(RPC_TIMEOUT, async {
        let slot0_data = pool.slot0().call().await?;
        let token0_addr = pool_immut.token0().call().await?;
        let token1_addr = pool_immut.token1().call().await?;
        Ok::<_, anyhow::Error>((slot0_data, token0_addr, token1_addr))
    })
    .await
    {
        Ok(Ok((slot0_data, token0_addr, token1_addr))) => {
            let p_sqrt = q64_96_to_float(slot0_data.sqrtPriceX96);
            let price_t1_in_t0_unadjusted = p_sqrt * p_sqrt;

            let (cbbtc_per_eth, eth_per_cbbtc) = if token0_addr == weth_address_clone {
                let cbbtc_per_eth =
                    price_t1_in_t0_unadjusted * 10f64.powi(WETH_DECIMALS - CBBTC_DECIMALS);
                let eth_per_cbbtc = 1.0 / cbbtc_per_eth;
                (cbbtc_per_eth, eth_per_cbbtc)
            } else if token1_addr == weth_address_clone {
                let eth_per_cbbtc =
                    price_t1_in_t0_unadjusted / 10f64.powi(WETH_DECIMALS - CBBTC_DECIMALS);
                let cbbtc_per_eth = 1.0 / eth_per_cbbtc;
                (cbbtc_per_eth, eth_per_cbbtc)
            } else {
                return Err(anyhow::anyhow!(
                    "Invalid token addresses for WETH/cbBTC pool on chain_id: {}",
                    chain_id
                ));
            };

            Ok::<_, anyhow::Error>(ConversionRates {
                cbbtc_per_eth,
                eth_per_cbbtc,
            })
        }
        Ok(Err(_)) | Err(_) => {
            return Err(anyhow::anyhow!(
                "No valid provider found for WETH/cbBTC rates on chain_id: {} within timeout period",
                chain_id
            ));
        }
    }?;

    Ok(rates)
}

pub fn q64_96_to_float(num: U160) -> f64 {
    let limbs = num.into_limbs();
    let lo = limbs[0] as f64; // bits 0..64
    let mid = limbs[1] as f64 * 2f64.powi(64); // bits 64..128
    let hi = limbs[2] as f64 * 2f64.powi(128); // bits 128..160 (top 32 bits used)

    let full = lo + mid + hi;
    full / 2f64.powi(96)
}

const CBBTC_DECIMALS: i32 = 8;
const WETH_DECIMALS: i32 = 18;
