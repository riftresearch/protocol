use alloy::{
    primitives::{address, U256},
    providers::{Provider, ProviderBuilder},
    sol,
};
use anyhow::Result;
use rift_sdk::quote::{fetch_weth_cbbtc_conversion_rates, q64_96_to_float};

sol!(
    #[sol(rpc)]
    IUniswapV3PoolLiquidity,
    r#"[
        {
            "inputs": [],
            "name": "liquidity",
            "outputs": [{"internalType": "uint128", "name": "", "type": "uint128"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]"#
);

sol!(
    #[sol(rpc)]
    IERC20,
    r#"[
        {
            "inputs": [{"internalType": "address", "name": "account", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "decimals",
            "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "symbol",
            "outputs": [{"internalType": "string", "name": "", "type": "string"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]"#
);

#[tokio::test]
async fn test_weth_cbbtc_conversion_base_mainnet() -> Result<()> {
    println!("\n=== Testing WETH/cbBTC Conversion Rates on Base Mainnet ===\n");

    const BASE_CHAIN_ID: u64 = 8453;

    println!("Fetching WETH/cbBTC conversion rates...");

    let mut rates = None;
    let rpcs = vec![
        "https://base.llamarpc.com",
        "https://base-mainnet.public.blastapi.io",
        "https://base.blockpi.network/v1/rpc/public",
        "https://1rpc.io/base",
    ];

    for rpc_url in rpcs {
        match fetch_rates_from_rpc(rpc_url).await {
            Ok(r) => {
                rates = Some(r);
                break;
            }
            Err(e) => {
                println!("  Failed to fetch from {}: {}", rpc_url, e);
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                continue;
            }
        }
    }

    let rates = rates.ok_or_else(|| anyhow::anyhow!("Failed to fetch rates from any RPC"))?;

    println!("Conversion Rates:");
    println!("1 ETH = {:.8} cbBTC", rates.cbbtc_per_eth);
    println!("1 cbBTC = {:.8} ETH", rates.eth_per_cbbtc);

    println!("Fetching Pool Information");

    let pool_address = address!("0x8c7080564B5A792A33Ef2FD473fbA6364d5495e5");
    let weth_address = address!("0x4200000000000000000000000000000000000006");
    let cbbtc_address = address!("0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf");

    let provider = ProviderBuilder::new().on_http("https://base.llamarpc.com".parse()?);

    let pool_liquidity = IUniswapV3PoolLiquidity::new(pool_address, &provider);
    let liquidity = pool_liquidity.liquidity().call().await?;
    println!("Pool Liquidity: {}", liquidity);

    let weth_contract = IERC20::new(weth_address, &provider);
    let cbbtc_contract = IERC20::new(cbbtc_address, &provider);

    let weth_balance = weth_contract.balanceOf(pool_address).call().await?;
    let cbbtc_balance = cbbtc_contract.balanceOf(pool_address).call().await?;

    let weth_balance_decimal = weth_balance.to_string().parse::<f64>()? / 1e18;
    let cbbtc_balance_decimal = cbbtc_balance.to_string().parse::<f64>()? / 1e8;

    println!("WETH Balance: {:.6} ETH", weth_balance_decimal);
    println!("cbBTC Balance: {:.8} cbBTC", cbbtc_balance_decimal);

    assert!(
        rates.cbbtc_per_eth > 0.0,
        "cbBTC per ETH rate should be positive"
    );
    assert!(
        rates.eth_per_cbbtc > 0.0,
        "ETH per cbBTC rate should be positive"
    );

    Ok(())
}

async fn fetch_rates_from_rpc(rpc_url: &str) -> Result<rift_sdk::quote::ConversionRates> {
    use rift_sdk::quote::{IUniswapV3PoolImmutables, IUniswapV3PoolState};
    use std::time::Duration;
    use tokio::time::timeout;

    let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);

    let pool_address = address!("0x8c7080564B5A792A33Ef2FD473fbA6364d5495e5");
    let weth_address = address!("0x4200000000000000000000000000000000000006");

    let pool = IUniswapV3PoolState::new(pool_address, &provider);
    let pool_immut = IUniswapV3PoolImmutables::new(pool_address, &provider);

    let (slot0_data, token0_addr, token1_addr) = timeout(Duration::from_secs(5), async {
        let slot0 = pool.slot0().call().await?;
        let token0 = pool_immut.token0().call().await?;
        let token1 = pool_immut.token1().call().await?;
        Ok::<_, anyhow::Error>((slot0, token0, token1))
    })
    .await??;

    let p_sqrt = q64_96_to_float(slot0_data.sqrtPriceX96);
    let price_t1_in_t0 = p_sqrt * p_sqrt;

    let (btc_like_per_eth, eth_per_btc_like) = if token0_addr == weth_address {
        let btc_like_per_eth = price_t1_in_t0 * 10f64.powi(18 - 8);
        let eth_per_btc_like = 1.0 / btc_like_per_eth;
        (btc_like_per_eth, eth_per_btc_like)
    } else if token1_addr == weth_address {
        let eth_per_btc_like = price_t1_in_t0 / 10f64.powi(18 - 8);
        let btc_like_per_eth = 1.0 / eth_per_btc_like;
        (btc_like_per_eth, eth_per_btc_like)
    } else {
        return Err(anyhow::anyhow!("WETH not found in pool"));
    };

    Ok(rift_sdk::quote::ConversionRates {
        cbbtc_per_eth: btc_like_per_eth,
        eth_per_cbbtc: eth_per_btc_like,
    })
}
