//! Transaction monitoring system for the Bitcoin transaction broadcaster
//!
//! This module monitors unconfirmed transactions and triggers RBF (Replace-By-Fee)
//! or CPFP (Child Pays For Parent) when transactions are stuck due to low fees.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Amount, FeeRate, Transaction, Txid};
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::RpcApi;
use tokio::sync::{broadcast, Mutex};
use tokio::time::interval;
use tokio_rusqlite::Connection;
use tracing::{debug, error, info, warn};

use crate::bitcoin_utils::AsyncBitcoinClient;
use crate::btc_txn_broadcaster::BitcoinSigner;
use crate::btc_txn_broadcaster_db::{
    add_broadcasted_transaction, get_unconfirmed_transactions, DbTransaction,
};
use crate::cpfp_analyzer::{CpfpChain, CpfpChainAnalyzer};
use crate::cpfp_builder::{CpfpBuilder, CpfpConfig};
use crate::fee_provider::BtcFeeProvider;
use crate::rbf_builder::{RbfBuilder, RbfConfig};
use crate::utxo_manager::UtxoManager;

#[derive(Debug, Clone)]
pub struct TransactionMonitorConfig {
    /// How often to check mempool fees for stuck transactions
    pub check_interval: Duration,
    /// Maximum age for monitored transactions in seconds
    pub max_transaction_age: u64,
    /// Minimum fee rate increase for RBF
    pub rbf_fee_increase_percent: u8,
    /// Minimum absolute fee increase in sats
    pub rbf_min_fee_increase_sats: u64,
    /// Target percentile for RBF transactions
    pub rbf_target_percentile: u8,
    /// Maximum number of RBF attempts per transaction
    pub max_rbf_attempts: u8,
    /// Time to wait between RBF attempts in seconds
    pub rbf_retry_delay_seconds: u64,
}

impl Default for TransactionMonitorConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(15),
            max_transaction_age: 24 * 60 * 60, // 24 hours
            rbf_fee_increase_percent: 10,
            rbf_min_fee_increase_sats: 1000,
            rbf_target_percentile: 50,
            max_rbf_attempts: 3,
            rbf_retry_delay_seconds: 300, // 5 minutes
        }
    }
}

impl TransactionMonitorConfig {
    pub fn validate(&self) -> eyre::Result<()> {
        if self.check_interval.as_secs() < 5 {
            return Err(eyre::eyre!("check_interval must be at least 5 seconds"));
        }

        if self.rbf_fee_increase_percent > 100 {
            return Err(eyre::eyre!("rbf_fee_increase_percent must be <= 100"));
        }

        if self.rbf_target_percentile > 100 {
            return Err(eyre::eyre!("rbf_target_percentile must be <= 100"));
        }

        if self.max_rbf_attempts == 0 {
            return Err(eyre::eyre!("max_rbf_attempts must be > 0"));
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RbfCandidate {
    pub original_tx: DbTransaction,
    pub current_fee_rate: f64,
    pub target_fee_rate: u64,
    pub required_fee_increase: Amount,
}

#[derive(Debug, Clone)]
pub enum FeeBumpStrategy {
    /// Use RBF on a single transaction
    Rbf(RbfCandidate),
    /// Use CPFP for a chain of transactions
    Cpfp {
        chain: CpfpChain,
        target_fee_rate: f64,
        required_child_fee: Amount,
    },
}

pub trait TransactionMonitoringHook: Send + Sync {
    fn on_rbf_attempt(&self, original_txid: Txid, target_fee_rate: u64);

    fn on_rbf_success(&self, original_txid: Txid, new_txid: Txid, new_fee: Amount);

    fn on_rbf_failure(&self, original_txid: Txid, error: &str);

    fn on_cpfp_attempt(&self, parent_txids: &[Txid], target_fee_rate: f64);

    fn on_cpfp_success(&self, parent_txids: &[Txid], child_txid: Txid, child_fee: Amount);

    fn on_cpfp_failure(&self, parent_txids: &[Txid], error: &str);
}

pub struct NoOpMonitoringHook;

impl TransactionMonitoringHook for NoOpMonitoringHook {
    fn on_rbf_attempt(&self, _: Txid, _: u64) {}
    fn on_rbf_success(&self, _: Txid, _: Txid, _: Amount) {}
    fn on_rbf_failure(&self, _: Txid, _: &str) {}
    fn on_cpfp_attempt(&self, _: &[Txid], _: f64) {}
    fn on_cpfp_success(&self, _: &[Txid], _: Txid, _: Amount) {}
    fn on_cpfp_failure(&self, _: &[Txid], _: &str) {}
}

pub struct TransactionMonitor<F: BtcFeeProvider, S: BitcoinSigner> {
    db_conn: Arc<Mutex<Connection>>,
    fee_provider: Arc<F>,
    config: TransactionMonitorConfig,
    cpfp_analyzer: Arc<CpfpChainAnalyzer>,
    rbf_builder: Arc<RbfBuilder>,
    cpfp_builder: Arc<CpfpBuilder>,
    utxo_manager: Arc<UtxoManager>,
    btc_rpc: Arc<AsyncBitcoinClient>,
    signer: Arc<S>,
    monitoring_hook: Arc<dyn TransactionMonitoringHook>,
}

impl<F: BtcFeeProvider + Send + Sync + 'static, S: BitcoinSigner + Send + Sync + 'static>
    TransactionMonitor<F, S>
{
    pub fn new(
        db_conn: Arc<Mutex<Connection>>,
        fee_provider: Arc<F>,
        config: TransactionMonitorConfig,
        utxo_manager: Arc<UtxoManager>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        signer: Arc<S>,
    ) -> eyre::Result<Self> {
        config.validate()?;

        let cpfp_analyzer = Arc::new(CpfpChainAnalyzer::new(db_conn.clone()));

        let rbf_config = RbfConfig {
            min_fee_increase_percent: config.rbf_fee_increase_percent,
            min_fee_increase_sats: config.rbf_min_fee_increase_sats,
            min_relay_fee_rate: 1,
        };

        let rbf_builder = Arc::new(
            RbfBuilder::new(rbf_config, utxo_manager.clone(), db_conn.clone())
                .expect("Failed to create RBF builder with valid config"),
        );

        let cpfp_config = CpfpConfig::default();
        let cpfp_builder = Arc::new(CpfpBuilder::new(
            cpfp_config,
            utxo_manager.clone(),
            db_conn.clone(),
        ));

        Ok(Self {
            db_conn,
            fee_provider,
            config,
            cpfp_analyzer,
            rbf_builder,
            cpfp_builder,
            utxo_manager,
            btc_rpc,
            signer,
            monitoring_hook: Arc::new(NoOpMonitoringHook),
        })
    }

    pub fn with_monitoring_hook(mut self, hook: Arc<dyn TransactionMonitoringHook>) -> Self {
        self.monitoring_hook = hook;
        self
    }

    /// Start monitoring with block subscription and periodic mempool checks
    pub async fn start(
        self: Arc<Self>,
        mut block_subscription: broadcast::Receiver<BlockLeaf>,
        mempool_check_interval: Duration,
    ) -> eyre::Result<()> {
        let (trigger_tx, mut trigger_rx) = tokio::sync::mpsc::channel::<MonitorTrigger>(100);

        let block_trigger = trigger_tx.clone();
        tokio::spawn(async move {
            loop {
                match block_subscription.recv().await {
                    Ok(block_leaf) => {
                        info!(
                            "New block event received: height={}, triggering transaction check",
                            block_leaf.height
                        );
                        let _ = block_trigger
                            .send(MonitorTrigger::NewBlock(block_leaf))
                            .await;
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!("Block event listener lagged, skipped {} blocks", skipped);
                    }
                    Err(e) => {
                        error!("Block subscription error: {}", e);
                        break;
                    }
                }
            }
        });

        let mempool_trigger = trigger_tx;
        tokio::spawn(async move {
            let mut ticker = interval(mempool_check_interval);
            loop {
                ticker.tick().await;
                let _ = mempool_trigger.send(MonitorTrigger::MempoolCheck).await;
            }
        });

        while let Some(trigger) = trigger_rx.recv().await {
            match trigger {
                MonitorTrigger::NewBlock(block_leaf) => {
                    debug!(
                        "New block event received at height {}, skipping (BlockWatcher handles confirmations)",
                        block_leaf.height
                    );
                }
                MonitorTrigger::MempoolCheck => {
                    // Periodic check for stuck transactions
                    if let Err(e) = self.check_unconfirmed_fee_adequacy().await {
                        warn!("Failed to check unconfirmed transaction fees: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn check_unconfirmed_fee_adequacy(&self) -> eyre::Result<()> {
        let unconfirmed_txs = {
            let conn = self.db_conn.lock().await;
            get_unconfirmed_transactions(&*conn, self.config.max_transaction_age).await?
        };

        if unconfirmed_txs.is_empty() {
            debug!("No unconfirmed transactions to check");
            return Ok(());
        }

        info!(
            "Checking fee adequacy for {} unconfirmed transactions",
            unconfirmed_txs.len()
        );

        let target_fee_rate = self
            .fee_provider
            .get_fee_rate_by_percentile(self.config.rbf_target_percentile)
            .await;

        debug!(
            "Current mempool fee rate at {}th percentile: {} sat/vB",
            self.config.rbf_target_percentile, target_fee_rate
        );

        let chains = self.cpfp_analyzer.analyze_unconfirmed_chains().await?;
        debug!("Found {} transaction chains", chains.len());

        self.check_transactions_internal(unconfirmed_txs, chains, target_fee_rate)
            .await
    }

    async fn check_transactions_internal(
        &self,
        unconfirmed_txs: Vec<DbTransaction>,
        chains: Vec<CpfpChain>,
        target_fee_rate: u64,
    ) -> eyre::Result<()> {
        // Create a map of txid to chain for quick lookup
        let mut txid_to_chain = std::collections::HashMap::new();
        for chain in &chains {
            for txid in chain.transactions.keys() {
                txid_to_chain.insert(*txid, chain);
            }
        }

        // Check each transaction and determine strat
        let mut fee_bump_strategies = Vec::new();
        let mut processed_txids = std::collections::HashSet::new();

        for tx_info in unconfirmed_txs {
            // Skip if already processed as part of a chain
            if processed_txids.contains(&tx_info.txid) {
                continue;
            }

            // Check if transaction is part of a chain
            if let Some(chain) = txid_to_chain.get(&tx_info.txid) {
                // Process the entire chain
                if let Some(strategy) = self
                    .evaluate_chain_for_fee_bump(chain, target_fee_rate)
                    .await?
                {
                    // Mark all transactions in the chain as processed
                    for chain_txid in chain.transactions.keys() {
                        processed_txids.insert(*chain_txid);
                    }
                    fee_bump_strategies.push(strategy);
                }
            } else {
                // Process single transaction
                if let Some(strategy) = self
                    .evaluate_single_transaction(&tx_info, target_fee_rate)
                    .await?
                {
                    fee_bump_strategies.push(strategy);
                }
            }
        }

        if !fee_bump_strategies.is_empty() {
            info!(
                "Found {} transactions/chains that need fee bumping",
                fee_bump_strategies.len()
            );

            // Execute fee bumping for these strats
            self.execute_fee_bump(fee_bump_strategies).await?;
        }

        Ok(())
    }

    /// Evaluate if a chain needs fee bumping
    async fn evaluate_chain_for_fee_bump(
        &self,
        chain: &CpfpChain,
        target_fee_rate: u64,
    ) -> eyre::Result<Option<FeeBumpStrategy>> {
        // Determine if chain needs fee bumping
        if !self
            .cpfp_analyzer
            .should_use_cpfp(chain, target_fee_rate as f64)
        {
            return Ok(None);
        }

        // Calculate required CPFP fee
        let child_weight = bitcoin::Weight::from_wu(400); // Approximate weight
        let required_child_fee =
            self.cpfp_analyzer
                .calculate_cpfp_fee(chain, target_fee_rate as f64, child_weight);

        if required_child_fee > Amount::ZERO {
            info!(
                "Chain with {} transactions needs CPFP: aggregate rate {:.2} sat/vB -> target {} sat/vB",
                chain.aggregate_stats.num_transactions,
                chain.aggregate_stats.aggregate_fee_rate,
                target_fee_rate
            );

            Ok(Some(FeeBumpStrategy::Cpfp {
                chain: chain.clone(),
                target_fee_rate: target_fee_rate as f64,
                required_child_fee,
            }))
        } else {
            Ok(None)
        }
    }

    /// Evaluate if a single transaction needs fee bumping
    async fn evaluate_single_transaction(
        &self,
        tx_info: &DbTransaction,
        target_fee_rate: u64,
    ) -> eyre::Result<Option<FeeBumpStrategy>> {
        // Try RBF first if enabled
        if tx_info.is_rbf_enabled {
            if let Some(candidate) = self.evaluate_for_rbf(tx_info, target_fee_rate).await? {
                return Ok(Some(FeeBumpStrategy::Rbf(candidate)));
            }
        }

        // If RBF not available or not needed, try CPFP
        self.evaluate_single_for_cpfp(tx_info, target_fee_rate)
            .await
    }

    /// Check if a transaction needs fee bumping based on current fee rate and age
    fn needs_fee_bump(
        current_fee_rate: f64,
        target_fee_rate: u64,
        tx_age_seconds: u64,
    ) -> (bool, f64) {
        // Apply age-based adjustment to the threshold
        // As transactions get older, we become more aggressive with fee bumping
        let age_adjusted_threshold = match tx_age_seconds {
            0..=300 => target_fee_rate as f64 * 0.9, // < 5 minutes: 90% threshold
            301..=900 => target_fee_rate as f64 * 0.8, // 5-15 minutes: 80% threshold
            901..=3600 => target_fee_rate as f64 * 0.7, // 15-60 minutes: 70% threshold
            _ => target_fee_rate as f64 * 0.6,       // > 1 hour: 60% threshold
        };

        (
            current_fee_rate < age_adjusted_threshold,
            age_adjusted_threshold,
        )
    }

    async fn evaluate_for_rbf(
        &self,
        tx_info: &DbTransaction,
        target_fee_rate: u64,
    ) -> eyre::Result<Option<RbfCandidate>> {
        // Skip if transaction doesn't have RBF enabled
        if !tx_info.is_rbf_enabled {
            return Ok(None);
        }

        // Skip if transaction was already replaced
        if tx_info.replaced_by.is_some() {
            return Ok(None);
        }

        // Check RBF attempt history
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        if let Some((attempt_count, last_attempt)) = {
            let conn = self.db_conn.lock().await;
            crate::btc_txn_broadcaster_db::get_rbf_attempt_info(&*conn, tx_info.txid).await?
        } {
            // Check if we've exceeded max attempts
            if attempt_count >= self.config.max_rbf_attempts {
                debug!(
                    "Transaction {} has reached max RBF attempts ({})",
                    tx_info.txid, attempt_count
                );
                return Ok(None);
            }

            // Check if we're still in cooldown period
            if let Some(last_attempt_time) = last_attempt {
                let time_since_last = current_time - last_attempt_time;
                if time_since_last < self.config.rbf_retry_delay_seconds {
                    debug!(
                        "Transaction {} in RBF cooldown period ({} seconds remaining)",
                        tx_info.txid,
                        self.config.rbf_retry_delay_seconds - time_since_last
                    );
                    return Ok(None);
                }
            }
        }

        let current_fee_rate = tx_info.fee_rate_sat_vb;

        // Check how long the transaction has been unconfirmed
        let tx_age_seconds = current_time - tx_info.broadcasted_at;

        // Check if fee bump is needed
        let (needs_bump, adjusted_threshold) =
            Self::needs_fee_bump(current_fee_rate, target_fee_rate, tx_age_seconds);

        if !needs_bump {
            debug!(
                "Transaction {} doesn't need RBF (current: {:.2} sat/vB, threshold: {:.2})",
                tx_info.txid, current_fee_rate, adjusted_threshold
            );
            return Ok(None);
        }

        // Calculate required fee increase
        let current_fee = tx_info.fee;
        let min_increase_percent =
            (current_fee.to_sat() as f64) * (self.config.rbf_fee_increase_percent as f64 / 100.0);
        let min_increase = min_increase_percent.max(self.config.rbf_min_fee_increase_sats as f64);

        // For very old transactions, use a higher increase
        let required_fee_increase = if tx_age_seconds > 1800 {
            Amount::from_sat((min_increase * 1.5).ceil() as u64)
        } else {
            Amount::from_sat(min_increase.ceil() as u64)
        };

        Ok(Some(RbfCandidate {
            original_tx: tx_info.clone(),
            current_fee_rate,
            target_fee_rate,
            required_fee_increase,
        }))
    }

    /// Evaluate if a single transaction needs CPFP (when RBF is not available)
    async fn evaluate_single_for_cpfp(
        &self,
        tx_info: &DbTransaction,
        target_fee_rate: u64,
    ) -> eyre::Result<Option<FeeBumpStrategy>> {
        let current_fee_rate = tx_info.fee_rate_sat_vb;

        // Check how long the transaction has been unconfirmed
        let tx_age_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            - tx_info.broadcasted_at;

        // Check if fee bump is needed
        let (needs_bump, adjusted_threshold) =
            Self::needs_fee_bump(current_fee_rate, target_fee_rate, tx_age_seconds);

        if !needs_bump {
            debug!(
                "Transaction {} doesn't need CPFP (current: {:.2} sat/vB, threshold: {:.2})",
                tx_info.txid, current_fee_rate, adjusted_threshold
            );
            return Ok(None);
        }

        // Calculate required child fee for CPFP
        let tx = deserialize_transaction(&tx_info.raw_tx)?;
        let parent_weight = tx.weight();

        // Estimate child transaction weight (1 input, 1 output, P2WPKH)
        let estimated_child_weight = bitcoin::Weight::from_wu(
            68 + // Input weight (P2WPKH)
            31 + // Output weight (P2WPKH)
            10, // Transaction overhead
        );

        // Calculate total package fee needed
        let total_weight = parent_weight + estimated_child_weight;
        let target_total_fee = FeeRate::from_sat_per_vb(target_fee_rate)
            .ok_or_else(|| eyre::eyre!("Invalid fee rate"))?
            .fee_wu(total_weight)
            .ok_or_else(|| eyre::eyre!("Fee calculation overflow"))?;

        let required_child_fee = if target_total_fee > tx_info.fee {
            target_total_fee - tx_info.fee
        } else {
            Amount::ZERO
        };

        // Only proceed if child fee is reasonable
        if required_child_fee > Amount::from_sat(10_000) {
            info!(
                "Single transaction {} needs CPFP: current {:.2} sat/vB -> target {} sat/vB (child fee: {} sats)",
                tx_info.txid,
                current_fee_rate,
                target_fee_rate,
                required_child_fee.to_sat()
            );

            // Create a simple chain representation for single transaction
            let chain = CpfpChain {
                roots: vec![tx_info.txid],
                transactions: [(
                    tx_info.txid,
                    crate::cpfp_analyzer::ChainTransaction {
                        txid: tx_info.txid,
                        fee: tx_info.fee,
                        fee_rate_sat_vb: tx_info.fee_rate_sat_vb,
                        weight: parent_weight,
                        is_confirmed: false,
                        is_rbf_enabled: false,
                        broadcasted_at: tx_info.broadcasted_at,
                        depth_in_chain: 0,
                    },
                )]
                .into_iter()
                .collect(),
                relationships: Default::default(),
                reverse_relationships: Default::default(),
                youngest_child: Some(tx_info.txid),
                aggregate_stats: crate::cpfp_analyzer::ChainStats {
                    total_fees: tx_info.fee,
                    total_weight: parent_weight,
                    aggregate_fee_rate: tx_info.fee_rate_sat_vb,
                    num_transactions: 1,
                    num_unconfirmed: 1,
                    oldest_broadcast: tx_info.broadcasted_at,
                    newest_broadcast: tx_info.broadcasted_at,
                },
            };

            return Ok(Some(FeeBumpStrategy::Cpfp {
                chain,
                target_fee_rate: target_fee_rate as f64,
                required_child_fee,
            }));
        }

        Ok(None)
    }

    /// Execute fee bumping for candidates
    async fn execute_fee_bump(&self, strategies: Vec<FeeBumpStrategy>) -> eyre::Result<()> {
        for strategy in strategies {
            match strategy {
                FeeBumpStrategy::Rbf(candidate) => {
                    info!(
                        "Executing RBF for transaction {}: current {:.2} sat/vB -> target {} sat/vB",
                        candidate.original_tx.txid,
                        candidate.current_fee_rate,
                        candidate.target_fee_rate
                    );

                    match self.execute_rbf(candidate).await {
                        Ok(new_txid) => {
                            info!("Successfully replaced transaction with {}", new_txid);
                        }
                        Err(e) => {
                            error!("Failed to execute RBF: {}", e);
                        }
                    }
                }
                FeeBumpStrategy::Cpfp {
                    chain,
                    target_fee_rate,
                    required_child_fee,
                } => {
                    info!(
                        "Executing CPFP for chain with {} transactions: aggregate {:.2} sat/vB -> target {:.2} sat/vB (child fee: {} sats)",
                        chain.aggregate_stats.num_transactions,
                        chain.aggregate_stats.aggregate_fee_rate,
                        target_fee_rate,
                        required_child_fee.to_sat()
                    );

                    match self
                        .execute_cpfp(chain, target_fee_rate, required_child_fee)
                        .await
                    {
                        Ok(child_txid) => {
                            info!("Successfully created CPFP child transaction {}", child_txid);
                        }
                        Err(e) => {
                            error!("Failed to execute CPFP: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Execute RBF for a single transaction
    async fn execute_rbf(&self, candidate: RbfCandidate) -> eyre::Result<bitcoin::Txid> {
        let target_fee_rate = FeeRate::from_sat_per_vb(candidate.target_fee_rate)
            .ok_or_else(|| eyre::eyre!("Invalid target fee rate"))?;

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Notify monitoring hook
        self.monitoring_hook
            .on_rbf_attempt(candidate.original_tx.txid, candidate.target_fee_rate);

        // Update RBF attempt count
        {
            let conn = self.db_conn.lock().await;
            crate::btc_txn_broadcaster_db::update_rbf_attempt(
                &*conn,
                candidate.original_tx.txid,
                current_time,
            )
            .await?;
        }

        // Build the replacement transaction
        let rbf_result = match self
            .rbf_builder
            .build_replacement(&candidate.original_tx, target_fee_rate, &*self.signer)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                error!(
                    "Failed to build RBF replacement for {}: {}",
                    candidate.original_tx.txid, e
                );
                self.monitoring_hook
                    .on_rbf_failure(candidate.original_tx.txid, &e.to_string());
                return Err(e);
            }
        };

        // Broadcast the replacement transaction
        match self
            .btc_rpc
            .send_raw_transaction(&rbf_result.replacement_tx)
            .await
        {
            Ok(_) => {
                let new_txid = rbf_result.replacement_tx.compute_txid();

                // Update the database
                self.rbf_builder
                    .update_database_after_rbf(rbf_result.original_txid, new_txid)
                    .await?;

                // Add the new transaction to the database
                {
                    let conn = self.db_conn.lock().await;
                    add_broadcasted_transaction(
                        &*conn,
                        &rbf_result.replacement_tx,
                        rbf_result.new_fee,
                        rbf_result.new_fee_rate,
                        Some(rbf_result.original_txid),
                        current_time,
                    )
                    .await?;
                }

                // Mark UTXOs as spent
                let outpoints: Vec<_> = rbf_result.input_utxos.iter().map(|u| u.outpoint).collect();

                self.utxo_manager
                    .mark_spent(
                        &outpoints
                            .iter()
                            .map(|&op| (op, new_txid))
                            .collect::<Vec<_>>(),
                    )
                    .await?;

                // Notify monitoring hook of success
                self.monitoring_hook.on_rbf_success(
                    rbf_result.original_txid,
                    new_txid,
                    rbf_result.new_fee,
                );

                info!(
                    "Successfully executed RBF: {} -> {} (new fee: {} sats, {:.2} sat/vB)",
                    rbf_result.original_txid,
                    new_txid,
                    rbf_result.new_fee.to_sat(),
                    rbf_result.new_fee_rate
                );

                Ok(new_txid)
            }
            Err(e) => {
                // Unlock any additional UTXOs that were selected
                // Parse original transaction to get its inputs
                let original_tx = deserialize_transaction(&candidate.original_tx.raw_tx)?;
                let original_outpoints: std::collections::HashSet<_> = original_tx
                    .input
                    .iter()
                    .map(|input| input.previous_output)
                    .collect();

                let additional_utxos: Vec<_> = rbf_result
                    .input_utxos
                    .iter()
                    .filter(|u| {
                        // Check if this UTXO was not in the original transaction
                        !original_outpoints.contains(&u.outpoint)
                    })
                    .map(|u| u.outpoint)
                    .collect();

                if !additional_utxos.is_empty() {
                    let _ = self
                        .utxo_manager
                        .unlock_utxos_by_outpoints(&additional_utxos)
                        .await;
                }

                error!(
                    "Failed to broadcast RBF replacement for {}: {}",
                    candidate.original_tx.txid, e
                );

                self.monitoring_hook
                    .on_rbf_failure(candidate.original_tx.txid, &e.to_string());

                Err(eyre::eyre!("RBF broadcast failed: {}", e))
            }
        }
    }

    /// Execute CPFP for a chain of transactions
    async fn execute_cpfp(
        &self,
        chain: CpfpChain,
        target_fee_rate: f64,
        required_child_fee: Amount,
    ) -> eyre::Result<bitcoin::Txid> {
        let target_fee_rate_bitcoin = FeeRate::from_sat_per_vb(target_fee_rate.ceil() as u64)
            .ok_or_else(|| eyre::eyre!("Invalid target fee rate"))?;

        let cpfp_result = if chain.transactions.len() == 1 && chain.roots.len() == 1 {
            let tx_data = chain.transactions.values().next().unwrap();
            let db_tx = DbTransaction {
                txid: tx_data.txid,
                raw_tx: Vec::new(),
                fee: tx_data.fee,
                fee_rate_sat_vb: tx_data.fee_rate_sat_vb,
                confirmation_block: None,
                confirmations: 0,
                is_rbf_enabled: tx_data.is_rbf_enabled,
                replaced_by: None,
                broadcasted_at: tx_data.broadcasted_at,
                last_checked: 0,
            };

            self.cpfp_builder
                .build_cpfp_for_single(&db_tx, target_fee_rate_bitcoin, &*self.signer)
                .await?
        } else {
            self.cpfp_builder
                .build_cpfp_for_chain(
                    &chain,
                    target_fee_rate_bitcoin,
                    required_child_fee,
                    &*self.signer,
                )
                .await?
        };

        // Notify monitoring hook of attempt
        let parent_txids: Vec<Txid> = chain.transactions.keys().cloned().collect();
        self.monitoring_hook
            .on_cpfp_attempt(&parent_txids, target_fee_rate);

        // Broadcast the child transaction
        match self
            .btc_rpc
            .send_raw_transaction(&cpfp_result.child_tx)
            .await
        {
            Ok(_) => {
                let child_txid = cpfp_result.child_tx.compute_txid();

                // Update the database with relationships
                self.cpfp_builder
                    .update_database_after_cpfp(child_txid, &cpfp_result.parent_txids)
                    .await?;

                // Add the child transaction to the database
                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();

                {
                    let conn = self.db_conn.lock().await;
                    add_broadcasted_transaction(
                        &*conn,
                        &cpfp_result.child_tx,
                        cpfp_result.child_fee,
                        cpfp_result.package_fee_rate,
                        None,
                        current_time,
                    )
                    .await?;
                }

                // Mark the input UTXOs as spent
                let outpoints: Vec<_> =
                    cpfp_result.input_utxos.iter().map(|u| u.outpoint).collect();

                self.utxo_manager
                    .mark_spent(
                        &outpoints
                            .iter()
                            .map(|&op| (op, child_txid))
                            .collect::<Vec<_>>(),
                    )
                    .await?;

                // Notify monitoring hook of success
                self.monitoring_hook.on_cpfp_success(
                    &cpfp_result.parent_txids,
                    child_txid,
                    cpfp_result.child_fee,
                );

                info!(
                    "Successfully executed CPFP: child {} accelerates {} parent(s) (package rate: {:.2} sat/vB)",
                    child_txid,
                    cpfp_result.parent_txids.len(),
                    cpfp_result.package_fee_rate
                );

                Ok(child_txid)
            }
            Err(e) => {
                // Unlock any UTXOs that were locked for this CPFP
                let outpoints: Vec<_> =
                    cpfp_result.input_utxos.iter().map(|u| u.outpoint).collect();

                // Only unlock UTXOs that aren't from the parent transactions
                let parent_outputs: std::collections::HashSet<_> =
                    chain.transactions.keys().map(|&txid| txid).collect();

                let external_utxos: Vec<_> = outpoints
                    .into_iter()
                    .filter(|op| !parent_outputs.contains(&op.txid))
                    .collect();

                if !external_utxos.is_empty() {
                    debug!(
                        "Unlocking {} external UTXOs after CPFP failure",
                        external_utxos.len()
                    );
                    let _ = self
                        .utxo_manager
                        .unlock_utxos_by_outpoints(&external_utxos)
                        .await;
                }

                error!("Failed to broadcast CPFP child transaction: {}", e);

                self.monitoring_hook
                    .on_cpfp_failure(&parent_txids, &e.to_string());

                Err(eyre::eyre!("CPFP broadcast failed: {}", e))
            }
        }
    }
}

#[derive(Debug, Clone)]
enum MonitorTrigger {
    /// New block arrived
    NewBlock(BlockLeaf),
    /// Periodic mempool fee check
    MempoolCheck,
}

pub fn deserialize_transaction(raw_tx: &[u8]) -> eyre::Result<Transaction> {
    use bitcoin::consensus::encode::Decodable;

    let tx = Transaction::consensus_decode(&mut &raw_tx[..])
        .map_err(|e| eyre::eyre!("Failed to deserialize transaction: {}", e))?;

    Ok(tx)
}
