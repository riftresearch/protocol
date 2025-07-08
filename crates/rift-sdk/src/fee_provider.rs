use crate::errors::RiftSdkError;
use crate::quote::fetch_weth_cbbtc_conversion_rates;
use alloy::providers::DynProvider;
use alloy::providers::Provider;
use esplora_client::r#async::AsyncClient;
use reqwest::Url;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

const BTC_FEE_UPDATE_INTERVAL: Duration = Duration::from_secs(15); // Update every 15 seconds
const DEFAULT_BTC_FEE_SATS_PER_VB: u64 = 10; // A fallback default
const TARGET_BLOCK_VSIZE: u64 = 1_000_000; // Target virtual size for simulated block (1M vBytes)

// Constants for ETH Fee Provider
const ETH_FEE_UPDATE_INTERVAL: Duration = Duration::from_secs(30); // Update every 30 seconds
const DEFAULT_ETH_SATS_PER_GAS: u64 = 1; // Fallback: 1 satoshi per gas unit

#[async_trait::async_trait]
pub trait BtcFeeProvider: Send + Sync {
    async fn get_fee_rate_sats_per_vb(&self) -> u64;
    async fn get_fee_rate_by_percentile(&self, percentile: u8) -> u64;
}

#[derive(Debug)]
pub struct BtcFeeOracle {
    cached_fee: RwLock<CachedFee>,
    esplora_client: Arc<AsyncClient>,
}

#[derive(Debug)]
struct CachedFee {
    fee_sats_per_vb: u64,
    last_updated: Instant,
    // Store the fee tiers for percentile calculations
    fee_tiers: Vec<(f32, u64)>, // (fee_rate, vsize)
}

impl BtcFeeOracle {
    pub fn new(esplora_api_url: String) -> Self {
        let client = esplora_client::Builder::new(&esplora_api_url)
            .build_async()
            .expect("Failed to build esplora client");
        Self {
            cached_fee: RwLock::new(CachedFee {
                fee_sats_per_vb: DEFAULT_BTC_FEE_SATS_PER_VB,
                last_updated: Instant::now()
                    .checked_sub(BTC_FEE_UPDATE_INTERVAL)
                    .unwrap_or_else(Instant::now),
                fee_tiers: Vec::new(),
            }),
            esplora_client: Arc::new(client),
        }
    }

    pub fn spawn_updater_in_set(self: Arc<Self>, join_set: &mut JoinSet<eyre::Result<()>>) {
        info!("Spawning BTC fee updater task in JoinSet.");
        join_set.spawn(async move { self.updater_loop().await });
    }

    async fn update_fee_cache(&self) -> Result<u64, RiftSdkError> {
        match self.esplora_client.get_mempool_info().await {
            Ok(mut mempool_info) => {
                if mempool_info.fee_histogram.is_empty() {
                    warn!("Esplora mempool fee histogram is empty. Using default fee.");
                    return Ok(self.cached_fee.read().await.fee_sats_per_vb);
                }

                // {
                //     "count": 8134,
                //     "vsize": 3444604,
                //     "total_fee":29204625,
                //     "fee_histogram": [[53.01, 102131], [38.56, 110990], [34.12, 138976], [24.34, 112619], [3.16, 246346], [2.92, 239701], [1.1, 775272]]
                // }
                // Sort the fee_histogram by fee rate in descending order
                // Not sure if it comes sorted
                mempool_info.fee_histogram.sort_unstable_by(|a, b| {
                    let fee_a = a.0;
                    let fee_b = b.0;
                    fee_b
                        .partial_cmp(&fee_a)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });

                let mut simulated_block_vsize: u64 = 0;
                let mut tiers_in_block: Vec<(f32, u64)> = Vec::new();

                for tier_data in &mempool_info.fee_histogram {
                    let fee_rate = tier_data.0;
                    let vsize_at_tier = tier_data.1;
                    if vsize_at_tier == 0 {
                        continue;
                    }

                    if simulated_block_vsize + vsize_at_tier <= TARGET_BLOCK_VSIZE {
                        tiers_in_block.push((fee_rate, vsize_at_tier));
                        simulated_block_vsize += vsize_at_tier;
                    } else {
                        let remaining_vsize = TARGET_BLOCK_VSIZE - simulated_block_vsize;
                        if remaining_vsize > 0 {
                            tiers_in_block.push((fee_rate, remaining_vsize));
                            simulated_block_vsize += remaining_vsize;
                        }
                        break;
                    }
                }

                if tiers_in_block.is_empty() || simulated_block_vsize == 0 {
                    warn!("Simulated block from mempool histogram is empty. Using default fee.");
                    return Ok(self.cached_fee.read().await.fee_sats_per_vb);
                }

                let median_vsize_mark = simulated_block_vsize / 2;
                let mut current_vsize_sum: u64 = 0;
                let mut median_fee_rate = DEFAULT_BTC_FEE_SATS_PER_VB;

                for (fee_rate, vsize_in_tier) in &tiers_in_block {
                    if current_vsize_sum + vsize_in_tier >= median_vsize_mark {
                        median_fee_rate = (*fee_rate as f64).max(1.0).round() as u64;
                        break;
                    }
                    current_vsize_sum += vsize_in_tier;
                }

                let mut cached = self.cached_fee.write().await;
                cached.fee_sats_per_vb = median_fee_rate;
                cached.last_updated = Instant::now();
                cached.fee_tiers = tiers_in_block;
                info!("Updated BTC fee rate to: {} sats/vB", median_fee_rate);
                Ok(median_fee_rate)
            }
            Err(e) => {
                error!(
                    "Failed to update BTC fee cache due to Esplora client error: {:?}",
                    e
                );
                Err(RiftSdkError::BitcoinRpcError(format!(
                    "Esplora client error: {}",
                    e
                )))
            }
        }
    }

    async fn updater_loop(&self) -> eyre::Result<()> {
        loop {
            if let Err(e) = self.update_fee_cache().await {
                error!(
                    "Periodic BTC fee update failed: {:?}. This error will not stop the loop.",
                    e
                );
            }
            tokio::time::sleep(BTC_FEE_UPDATE_INTERVAL).await;
        }
    }
}

#[async_trait::async_trait]
impl BtcFeeProvider for BtcFeeOracle {
    async fn get_fee_rate_sats_per_vb(&self) -> u64 {
        let (stale_fee, needs_update) = {
            let cached = self.cached_fee.read().await;
            (
                cached.fee_sats_per_vb,
                cached.last_updated.elapsed() >= BTC_FEE_UPDATE_INTERVAL,
            )
        };

        if needs_update {
            info!("BTC fee cache is stale. Attempting synchronous update.");
            match self.update_fee_cache().await {
                Ok(new_fee) => new_fee,
                Err(_) => {
                    warn!(
                        "Synchronous BTC fee update failed. Using stale fee: {} sats/vB",
                        stale_fee
                    );
                    stale_fee
                }
            }
        } else {
            self.cached_fee.read().await.fee_sats_per_vb
        }
    }

    async fn get_fee_rate_by_percentile(&self, percentile: u8) -> u64 {
        let percentile = percentile.min(100);

        let (stale_median_fee, needs_update, fee_tiers) = {
            let cached = self.cached_fee.read().await;
            (
                cached.fee_sats_per_vb,
                cached.last_updated.elapsed() >= BTC_FEE_UPDATE_INTERVAL,
                cached.fee_tiers.clone(),
            )
        };

        // Update cache if needed
        if needs_update {
            info!(
                "BTC fee cache is stale. Attempting synchronous update for percentile calculation."
            );
            if let Err(e) = self.update_fee_cache().await {
                warn!(
                    "Synchronous BTC fee update failed: {:?}. Using cached data.",
                    e
                );
            }
        }

        // Get the latest fee tiers after potential update
        let fee_tiers = if needs_update {
            self.cached_fee.read().await.fee_tiers.clone()
        } else {
            fee_tiers
        };

        // If no tiers available, return the median fee with some adjustment
        if fee_tiers.is_empty() {
            let adjustment = match percentile {
                0..=25 => 0.8,
                26..=50 => 1.0,
                51..=75 => 1.2,
                _ => 1.5,
            };
            return ((stale_median_fee as f64) * adjustment).round().max(1.0) as u64;
        }

        // Calculate total vsize in the simulated block
        let total_vsize: u64 = fee_tiers.iter().map(|(_, vsize)| vsize).sum();

        if total_vsize == 0 {
            return stale_median_fee;
        }

        // Find the fee rate at the requested percentile
        let target_vsize = (total_vsize as f64 * (percentile as f64 / 100.0)).round() as u64;
        let mut cumulative_vsize: u64 = 0;

        for (fee_rate, vsize_in_tier) in &fee_tiers {
            cumulative_vsize += vsize_in_tier;
            if cumulative_vsize >= target_vsize {
                return (*fee_rate as f64).max(1.0).round() as u64;
            }
        }

        // Fallback to the lowest fee rate in the block
        fee_tiers
            .last()
            .map(|(fee_rate, _)| (*fee_rate as f64).max(1.0).round() as u64)
            .unwrap_or(stale_median_fee)
    }
}

#[async_trait::async_trait]
pub trait EthFeeProvider: Send + Sync {
    async fn get_fee_rate_sats_per_eth_gas(&self) -> u64;
}

#[derive(Debug)]
pub struct EthFeeOracle {
    cached_fee: RwLock<CachedEthFee>,
    provider: DynProvider,
    chain_id: u64,
}

#[derive(Debug, Clone, Copy)]
struct CachedEthFee {
    sats_per_eth_gas: u64,
    gas_price_wei: u128,
    cbbtc_per_eth: f64,
    last_updated: Instant,
}

impl EthFeeOracle {
    pub fn new(provider: DynProvider, chain_id: u64) -> Self {
        Self {
            cached_fee: RwLock::new(CachedEthFee {
                sats_per_eth_gas: DEFAULT_ETH_SATS_PER_GAS,
                gas_price_wei: 0,
                cbbtc_per_eth: 0.0,
                last_updated: Instant::now()
                    .checked_sub(ETH_FEE_UPDATE_INTERVAL)
                    .unwrap_or_else(Instant::now),
            }),
            provider,
            chain_id,
        }
    }

    pub fn spawn_updater_in_set(self: Arc<Self>, join_set: &mut JoinSet<eyre::Result<()>>) {
        info!("Spawning ETH fee (sats/gas) updater task in JoinSet");
        join_set.spawn(async move { self.updater_loop().await });
    }

    async fn update_fee_cache(&self) -> Result<u64, RiftSdkError> {
        let gas_price_wei = {
            let gas_price = self.provider.get_gas_price().await.map_err(|e| {
                error!("Failed to fetch ETH gas price (wei): {:?}", e);
                RiftSdkError::Generic(format!("Failed to fetch ETH gas price (wei): {:?}", e))
            })?;
            gas_price
        };

        let conversion_rates =
            match fetch_weth_cbbtc_conversion_rates(self.provider.clone(), self.chain_id).await {
                Ok(rates) => rates,
                Err(e) => {
                    if self.chain_id == 1337 {
                        // Suppress all error logs and returns for devnet chain_id 1337
                        return Ok(self.cached_fee.read().await.sats_per_eth_gas);
                    } else {
                        error!(
                            "Failed to fetch WETH/cbBTC conversion rates for chain_id {}: {:?}",
                            self.chain_id, e
                        );
                        return Err(RiftSdkError::Generic(format!(
                            "WETH/cbBTC conversion rate error for chain {}: {}",
                            self.chain_id, e
                        )));
                    }
                }
            };

        let cbbtc_per_eth = conversion_rates.cbbtc_per_eth;

        if gas_price_wei == 0 || cbbtc_per_eth <= 0.0 {
            warn!(
                "Invalid gas price or cbBTC/ETH rate. gas_price_wei: {}, cbbtc_per_eth: {}",
                gas_price_wei, cbbtc_per_eth
            );
            return Ok(self.cached_fee.read().await.sats_per_eth_gas);
        }

        let gas_price_wei_f64 = gas_price_wei as f64;

        let sats_per_gas_f64 = (gas_price_wei_f64 * cbbtc_per_eth) / 10_000_000_000.0;

        let calculated_sats_per_gas = if sats_per_gas_f64 > 0.0 {
            sats_per_gas_f64.round().max(1.0) as u64
        } else {
            1u64
        };

        let mut cached = self.cached_fee.write().await;
        cached.sats_per_eth_gas = calculated_sats_per_gas;
        cached.gas_price_wei = gas_price_wei;
        cached.cbbtc_per_eth = cbbtc_per_eth;
        cached.last_updated = Instant::now();

        info!(
            "Updated ETH fee rate for chain {}: {} sats/gas (gas: {} Wei, cbBTC/ETH: {:.8})",
            self.chain_id, calculated_sats_per_gas, gas_price_wei, cbbtc_per_eth
        );

        Ok(calculated_sats_per_gas)
    }

    async fn updater_loop(&self) -> eyre::Result<()> {
        let _chain_id = self.provider.get_chain_id().await?;
        loop {
            if let Err(e) = self.update_fee_cache().await {
                if self.chain_id != 1337 {
                    error!(
                        "Periodic ETH fee (sats/gas) update failed for chain {}: {:?}. This error will not stop the loop.",
                        self.chain_id, e
                    );
                }
            }
            tokio::time::sleep(ETH_FEE_UPDATE_INTERVAL).await;
        }
    }
}

#[async_trait::async_trait]
impl EthFeeProvider for EthFeeOracle {
    async fn get_fee_rate_sats_per_eth_gas(&self) -> u64 {
        let (stale_fee, needs_update) = {
            let cached = self.cached_fee.read().await;
            (
                cached.sats_per_eth_gas,
                cached.last_updated.elapsed() >= ETH_FEE_UPDATE_INTERVAL,
            )
        };

        if needs_update {
            info!("ETH fee (sats/gas) cache is stale. Attempting synchronous update.",);
            match self.update_fee_cache().await {
                Ok(new_fee) => new_fee,
                Err(e) => {
                    warn!(
                        "Synchronous ETH fee (sats/gas) update failed for chain {}: {:?}. Using stale fee: {} sats/gas",
                        self.chain_id, e, stale_fee
                    );
                    stale_fee
                }
            }
        } else {
            self.cached_fee.read().await.sats_per_eth_gas
        }
    }
}

pub fn eth_gas_to_satoshis(gas_units: u64, gas_price_wei: u128, cbbtc_per_eth: f64) -> u64 {
    if gas_units == 0 || gas_price_wei == 0 || cbbtc_per_eth <= 0.0 {
        return 0;
    }

    let total_wei = gas_units as u128 * gas_price_wei;
    let total_eth = total_wei as f64 / 1e18;
    let total_cbbtc = total_eth * cbbtc_per_eth;
    let total_sats = (total_cbbtc * 1e8).round() as u64;

    total_sats
}
