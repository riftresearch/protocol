use crate::bitcoin_utils::AsyncBitcoinClient;
use crate::errors::RiftSdkError;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

const BTC_FEE_UPDATE_INTERVAL: Duration = Duration::from_secs(60 * 5); // Update every 5 minutes
const DEFAULT_BTC_FEE_SATS_PER_VB: u64 = 10; // A fallback default
const BTC_FEE_CONF_TARGET: u32 = 6; // Target confirmation in 6 blocks

#[async_trait::async_trait]
pub trait BtcFeeProvider: Send + Sync {
    async fn get_fee_rate_sats_per_vb(&self) -> u64;
}

#[derive(Debug)]
pub struct BtcFeeOracle {
    client: Arc<AsyncBitcoinClient>,
    cached_fee: RwLock<CachedFee>,
}

#[derive(Debug)]
struct CachedFee {
    fee_sats_per_vb: u64,
    last_updated: Instant,
}

impl BtcFeeOracle {
    pub fn new(client: Arc<AsyncBitcoinClient>) -> Self {
        Self {
            client,
            cached_fee: RwLock::new(CachedFee {
                fee_sats_per_vb: DEFAULT_BTC_FEE_SATS_PER_VB,
                // Force update on first get_fee_rate_sats_per_vb call or first tick of background updater
                last_updated: Instant::now()
                    .checked_sub(BTC_FEE_UPDATE_INTERVAL)
                    .unwrap_or_else(Instant::now),
            }),
        }
    }

    pub fn spawn_updater_in_set(self: Arc<Self>, join_set: &mut JoinSet<eyre::Result<()>>) {
        info!("Spawning BTC fee updater task in JoinSet.");
        join_set.spawn(async move { self.updater_loop().await });
    }

    async fn update_fee_cache(&self) -> Result<u64, RiftSdkError> {
        match self
            .client
            .estimate_fee_rate_sats_per_vb(BTC_FEE_CONF_TARGET, Some("ECONOMICAL"))
            .await
        {
            Ok(fee_rate) => {
                let mut cached = self.cached_fee.write().await;
                cached.fee_sats_per_vb = fee_rate;
                cached.last_updated = Instant::now();
                info!("Updated BTC fee rate to: {} sats/vB", fee_rate);
                Ok(fee_rate)
            }
            Err(e) => {
                error!(
                    "Failed to update BTC fee rate: {:?}. Using last known fee.",
                    e
                );
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
