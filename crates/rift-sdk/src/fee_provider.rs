use crate::bitcoin_utils::AsyncBitcoinClient;
use crate::errors::RiftSdkError;
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

const BTC_FEE_UPDATE_INTERVAL: Duration = Duration::from_secs(60 * 5); // Update every 5 minutes
const DEFAULT_BTC_FEE_SATS_PER_VB: u64 = 10; // A fallback default
const TARGET_BLOCK_VSIZE: u64 = 1_000_000; // Target virtual size for simulated block (1M vBytes)

#[async_trait::async_trait]
pub trait BtcFeeProvider: Send + Sync {
    async fn get_fee_rate_sats_per_vb(&self) -> u64;
}

#[derive(Debug)]
pub struct BtcFeeOracle {
    cached_fee: RwLock<CachedFee>,
    esplora_client: Arc<EsploraClient>,
}

#[derive(Debug)]
struct CachedFee {
    fee_sats_per_vb: u64,
    last_updated: Instant,
}

#[derive(Deserialize, Debug)]
struct EsploraMempoolInfo {
    count: u64,
    vsize: u64,
    total_fee: u64,
    fee_histogram: Vec<Vec<f64>>,
}

#[derive(Debug)]
pub struct EsploraClient {
    esplora_api_url: String,
    http_client: reqwest::Client,
}

impl EsploraClient {
    pub fn new(esplora_api_url: String) -> Self {
        Self {
            esplora_api_url,
            http_client: reqwest::Client::new(),
        }
    }

    async fn get_mempool_info(&self) -> Result<EsploraMempoolInfo, RiftSdkError> {
        let mempool_url = format!("{}/mempool", self.esplora_api_url);
        match self.http_client.get(&mempool_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<EsploraMempoolInfo>().await {
                        Ok(mempool_info) => Ok(mempool_info),
                        Err(e) => {
                            error!(
                                "Failed to parse Esplora mempool response from {}: {:?}.",
                                mempool_url, e
                            );
                            Err(RiftSdkError::BitcoinRpcError(format!(
                                "EsploraMempoolInfo from {}: {}",
                                mempool_url, e
                            )))
                        }
                    }
                } else {
                    error!(
                        "Esplora API request to {} failed with status: {}.",
                        mempool_url,
                        response.status()
                    );
                    Err(RiftSdkError::BitcoinRpcError(format!(
                        "Esplora API error for {}: {}",
                        mempool_url,
                        response.status()
                    )))
                }
            }
            Err(e) => {
                error!(
                    "Failed to fetch BTC fee rate from Esplora mempool ({}): {:?}.",
                    mempool_url, e
                );
                Err(RiftSdkError::BitcoinRpcError(format!(
                    "Esplora request to {}: {}",
                    mempool_url, e
                )))
            }
        }
    }
}

impl BtcFeeOracle {
    pub fn new(esplora_client: Arc<EsploraClient>) -> Self {
        Self {
            cached_fee: RwLock::new(CachedFee {
                fee_sats_per_vb: DEFAULT_BTC_FEE_SATS_PER_VB,
                last_updated: Instant::now()
                    .checked_sub(BTC_FEE_UPDATE_INTERVAL)
                    .unwrap_or_else(Instant::now),
            }),
            esplora_client,
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
                    let fee_a = a.get(0).copied().unwrap_or(0.0);
                    let fee_b = b.get(0).copied().unwrap_or(0.0);
                    fee_b.partial_cmp(&fee_a).unwrap_or(std::cmp::Ordering::Equal)
                });

                let mut simulated_block_vsize: u64 = 0;
                let mut tiers_in_block: Vec<(f64, u64)> = Vec::new();

                for tier_data in &mempool_info.fee_histogram {
                    if tier_data.len() == 2 {
                        let fee_rate = tier_data[0];
                        let vsize_at_tier = tier_data[1].round() as u64;

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
                    } else {
                        warn!("Malformed fee histogram entry: {:?}", tier_data);
                    }
                }

                if tiers_in_block.is_empty() || simulated_block_vsize == 0 {
                    warn!("Simulated block from mempool histogram is empty. Using default fee.");
                    return Ok(self.cached_fee.read().await.fee_sats_per_vb);
                }

                let median_vsize_mark = simulated_block_vsize / 2;
                let mut current_vsize_sum: u64 = 0;
                let mut median_fee_rate = DEFAULT_BTC_FEE_SATS_PER_VB;

                for (fee_rate, vsize_in_tier) in tiers_in_block {
                    if current_vsize_sum + vsize_in_tier >= median_vsize_mark {
                        median_fee_rate = fee_rate.max(1.0).round() as u64;
                        break;
                    }
                    current_vsize_sum += vsize_in_tier;
                }
                
                let mut cached = self.cached_fee.write().await;
                cached.fee_sats_per_vb = median_fee_rate;
                cached.last_updated = Instant::now();
                info!(
                    "Updated BTC fee rate to: {} sats/vB",
                    median_fee_rate
                );
                Ok(median_fee_rate)
            }
            Err(e) => {
                error!("Failed to update BTC fee cache due to Esplora client error: {:?}", e);
                Err(e)
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
}

// TODO: ETH

