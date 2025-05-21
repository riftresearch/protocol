use alloy::primitives::U160;
use rift_sdk::quote::{fetch_weth_wbtc_conversion_rates, q64_96_to_float};

#[test]
fn test_q64_96_to_float() {
    let num = U160::from(1506673274302120988651364689808458u128);
    let float = q64_96_to_float(num);
    println!("Float: {}", float);
}

#[tokio::test]
async fn test_fetch_weth_wbtc_rates() {
    let chain_id_to_test = 1; // ETH Mainnet is 1
    println!(
        "Fetching WETH/WBTC conversion rates from Uniswap V3 pool on chain ID: {}",
        chain_id_to_test
    );
    match fetch_weth_wbtc_conversion_rates(chain_id_to_test).await {
        Ok(rates) => {
            println!("1 WBTC = {:.8} WETH", rates.eth_per_wbtc);
            println!("1 WETH = {:.8} WBTC", rates.wbtc_per_eth);

            assert!(
                rates.eth_per_wbtc > 0.0,
                "ETH per WBTC rate should be positive"
            );
            assert!(
                rates.wbtc_per_eth > 0.0,
                "WBTC per ETH rate should be positive"
            );
            println!("Test passed: Rates are positive");
        }
        Err(e) => {
            eprintln!(
                "Error fetching WETH/WBTC rates in test for chain_id {}: {}",
                chain_id_to_test, e
            );
            panic!(
                "Failed to fetch WETH/WBTC rates for chain_id {}: {}",
                chain_id_to_test, e
            );
        }
    }
}
