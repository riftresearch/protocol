//! Simple async broadcaster that selects coins, computes the exact fee and
//! (optionally) adds a change output – all in one place.
//
//  * Assumes the wallet uses P2WPKH for both its receive and change outputs.
//  * Depends on the bitcoin_coin_selection crate for input selection but
//    computes the change output (value **and** decision to include it) here.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::{
    absolute::LockTime, address::NetworkChecked, transaction, Amount, FeeRate, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Txid, Weight, Witness,
};
use bitcoin_coin_selection::{self as cs, WeightedUtxo};
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::RpcApi;
use esplora_client::AsyncClient as EsploraClient;
use tokio::{
    sync::{
        broadcast,
        mpsc::{channel, Receiver, Sender},
        oneshot,
    },
    task::JoinSet,
};
use tracing::{debug, info, warn};

use crate::bitcoin_utils::AsyncBitcoinClient;
use crate::block_watcher::{BlockWatcher, BlockWatcherConfig};
use crate::btc_txn_broadcaster_db::{add_broadcasted_transaction, add_tx_relationships};
use crate::fee_provider::{BtcFeeOracle, BtcFeeProvider};
use crate::transaction_monitor::{TransactionMonitor, TransactionMonitorConfig};
use crate::utxo_manager::{UtxoManager, UtxoManagerConfig};
use crate::DatabaseLocation;

// Re-export the fee provider trait for custom implementations
pub use crate::fee_provider::BtcFeeProvider as BtcFeeProviderTrait;

/// TODO: Make these fields within the Signer trait instead of enshrining P2WPKH
/// Weight constants for P2WPKH (see BIP‑141)
pub const CHANGE_OUTPUT_W: Weight = Weight::from_vb_unchecked(31); // P2WPKH output
pub const CHANGE_SPEND_W: Weight = Weight::from_vb_unchecked(68); // spending it later
const TX_BASE_W: Weight = Weight::from_vb_unchecked(10);

/// Helper: given the selected inputs and the intended pay‑to outputs, decide
/// whether a change output is needed and – if so – return its value.
pub fn calc_change<U: WeightedUtxo>(
    inputs: &[&U],
    pay_value: Amount, // sum of *recipient* outputs
    fee_rate: FeeRate,
) -> eyre::Result<Option<Amount>> {
    // 1. Sum values/weights of the chosen inputs
    let (inp_val, inp_w) = inputs
        .iter()
        .try_fold((Amount::ZERO, Weight::ZERO), |acc, u| {
            Some((
                acc.0 + u.value(),
                acc.1.checked_add(u.satisfaction_weight())?,
            ))
        })
        .ok_or_else(|| eyre::eyre!("weight overflow"))?;

    // 2. Weight of the pay‑to outputs (all assumed P2WPKH for now)
    let outs_w = Weight::from_vb(31 * (pay_value != Amount::ZERO) as u64 * inputs.len() as u64) // 31 vB per output
        .unwrap_or(Weight::ZERO);

    // 3. Fee without change
    let w_no_change = TX_BASE_W + inp_w + outs_w;
    let fee_no_change = fee_rate
        .fee_wu(w_no_change)
        .ok_or_else(|| eyre::eyre!("fee overflow"))?;

    let remainder = inp_val
        .checked_sub(pay_value + fee_no_change)
        .ok_or_else(|| eyre::eyre!("inputs do not cover payment"))?;

    // Core's MIN_CHANGE constant
    const CHANGE_LOWER: Amount = Amount::from_sat(50_000);

    if remainder < CHANGE_LOWER {
        return Ok(None); // "tip" the miner, no change
    }

    // 4. Fee with change output
    let w_with_change = w_no_change + CHANGE_OUTPUT_W;
    let fee_with_change = fee_rate
        .fee_wu(w_with_change)
        .ok_or_else(|| eyre::eyre!("fee overflow"))?;

    let change_val = inp_val
        .checked_sub(pay_value + fee_with_change)
        .ok_or_else(|| eyre::eyre!("inputs do not cover payment + fee"))?;

    if change_val < CHANGE_LOWER {
        Ok(None)
    } else {
        Ok(Some(change_val))
    }
}

/// A trait for signing transactions from a Bitcoin wallet.
pub trait BitcoinSigner {
    fn sign_transaction(
        &self,
        tx: &Transaction,
        utxo_inputs: &[InputUtxo],
    ) -> eyre::Result<Transaction>;
    fn get_script_pubkey(&self) -> ScriptBuf; // script for change output
    fn get_address(&self) -> bitcoin::Address<NetworkChecked>;
}

#[async_trait]
pub trait BitcoinTransactionBroadcasterTrait {
    async fn new<S: BitcoinSigner + Send + Sync + Clone + 'static>(
        btc_rpc: Arc<AsyncBitcoinClient>,
        esplora_client: Arc<EsploraClient>,
        btc_signer: S,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Self;

    async fn broadcast_transaction(&self, tx_outs: &[TxOut]) -> eyre::Result<Txid>;
    async fn can_fund_transaction(&self, tx: &[TxOut]) -> eyre::Result<bool>;
}

#[derive(Debug)]
struct Request {
    tx_outs: Vec<TxOut>,
    response_tx: oneshot::Sender<eyre::Result<Txid>>,
}

pub struct SimpleBitcoinTransactionBroadcaster {
    request_sender: Sender<Request>,
}

#[async_trait]
impl BitcoinTransactionBroadcasterTrait for SimpleBitcoinTransactionBroadcaster {
    async fn new<S: BitcoinSigner + Send + Sync + Clone + 'static>(
        btc_rpc: Arc<AsyncBitcoinClient>,
        esplora_client: Arc<EsploraClient>,
        btc_signer: S,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Self {
        let (request_sender, request_receiver) = channel(128);

        join_set.spawn(async move {
            consume_broadcast_queue(btc_rpc, esplora_client, btc_signer, request_receiver).await
        });

        Self { request_sender }
    }

    async fn broadcast_transaction(&self, tx_outs: &[TxOut]) -> eyre::Result<Txid> {
        let (response_tx, rx) = oneshot::channel();
        self.request_sender
            .send(Request {
                tx_outs: tx_outs.to_vec(),
                response_tx,
            })
            .await
            .map_err(|_| eyre::eyre!("queue error"))?;
        rx.await?
    }

    async fn can_fund_transaction(&self, _tx: &[TxOut]) -> eyre::Result<bool> {
        Ok(true) // TODO
    }
}

// Lightweight UTXO wrapper implementing WeightedUtxo
#[derive(Debug, Clone)]
pub struct InputUtxo {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub weight: Weight,
}

impl WeightedUtxo for InputUtxo {
    fn satisfaction_weight(&self) -> Weight {
        self.weight
    }
    fn value(&self) -> Amount {
        self.value
    }
}

impl InputUtxo {
    pub fn new(outpoint: OutPoint, value: Amount) -> Self {
        Self {
            outpoint,
            value,
            weight: CHANGE_SPEND_W,
        }
    }
}

async fn consume_broadcast_queue<S: BitcoinSigner + Send + Sync + 'static>(
    btc_rpc: Arc<AsyncBitcoinClient>,
    esplora: Arc<EsploraClient>,
    signer: S,
    mut rx: Receiver<Request>,
) -> eyre::Result<()> {
    let addr = signer.get_address();
    let long_term_fee_rate = FeeRate::from_sat_per_vb(1).unwrap();

    while let Some(req) = rx.recv().await {
        let pay_outs = req.tx_outs.clone();
        let pay_value: Amount = pay_outs.iter().map(|o| o.value).sum();
        info!("New request: {:#?}", req);

        // TODO: Use our oracle instead:
        // --- fee estimation ---
        let fee_rate_sat_vb = FeeRate::from_sat_per_vb(
            esplora
                .get_fee_estimates()
                .await?
                .get(&1)
                .copied()
                .unwrap_or(2.0) // fall‑back - increased to be more conservative
                .ceil() as u64,
        )
        .expect("from sat per vb overflow");

        // --- gather UTXOs & run coin‑selection ---
        let utxos_remote = esplora.get_address_utxo(&addr).await?;
        let utxo_wrapped: Vec<InputUtxo> = utxos_remote
            .iter()
            .map(|u| InputUtxo::new(OutPoint::new(u.txid, u.vout), Amount::from_sat(u.value)))
            .collect();

        info!("UTXOs: {:#?}", utxo_wrapped);

        let selected_input_utxos = cs::select_coins(
            pay_value,
            bitcoin::transaction::effective_value(
                fee_rate_sat_vb,
                CHANGE_OUTPUT_W,
                Amount::from_sat(50_000),
            )
            .unwrap_or(Amount::from_sat(1000).to_signed().unwrap())
            .to_unsigned()
            .unwrap_or(Amount::from_sat(1000)), // fallback cost_of_change
            fee_rate_sat_vb,
            long_term_fee_rate,
            &utxo_wrapped,
        );
        if selected_input_utxos.is_none() {
            let _ = req.response_tx.send(Err(eyre::eyre!("insufficient funds")));
            continue;
        }
        let (_, selected_input_utxos) = selected_input_utxos.unwrap();

        // --- decide change ---
        let change_opt = calc_change(&selected_input_utxos, pay_value, fee_rate_sat_vb)?;

        // --- build the transaction ---
        let mut outputs = pay_outs;
        if let Some(change_amt) = change_opt {
            outputs.push(TxOut {
                value: change_amt,
                script_pubkey: signer.get_script_pubkey(),
            });
        }

        let inputs: Vec<TxIn> = selected_input_utxos
            .iter()
            .map(|u| TxIn {
                previous_output: u.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xFFFFFFFD), // opt‑in RBF (BIP‑125)
                witness: Witness::new(),
            })
            .collect();

        let unsigned = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        let selected_utxos: Vec<InputUtxo> =
            selected_input_utxos.iter().map(|&u| u.clone()).collect();
        let signed = signer.sign_transaction(&unsigned, &selected_utxos)?;
        btc_rpc.send_raw_transaction(&signed).await?;
        let _ = req.response_tx.send(Ok(signed.compute_txid()));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct BroadcasterConfig {
    /// Database location for UTXO and transaction tracking
    pub db_location: DatabaseLocation,
    /// How often to monitor unconfirmed transactions
    pub monitoring_interval: Duration,
    /// Confirmations needed before removing spent UTXOs
    pub confirmation_threshold: u32,
    /// Target fee percentile for new transactions
    pub target_fee_percentile: u8,
    /// Long-term fee rate for coin selection
    pub long_term_fee_rate_sat_vb: u64,
    /// Minimum confirmations for spending UTXOs
    pub min_utxo_confirmations: u32,
    /// Esplora API URL for fee estimation
    pub esplora_api_url: String,
}

impl Default for BroadcasterConfig {
    fn default() -> Self {
        Self {
            db_location: DatabaseLocation::InMemory,
            monitoring_interval: Duration::from_secs(15),
            confirmation_threshold: 6,
            target_fee_percentile: 25,
            long_term_fee_rate_sat_vb: 1,
            min_utxo_confirmations: 0,
            esplora_api_url: "https://mempool.space/api".to_string(),
        }
    }
}

pub struct EnhancedBitcoinTransactionBroadcaster {
    request_sender: Sender<Request>,
    utxo_manager: Arc<UtxoManager>,
    #[allow(dead_code)]
    config: BroadcasterConfig,
    #[allow(dead_code)]
    fee_oracle: Arc<BtcFeeOracle>,
}

#[async_trait]
impl BitcoinTransactionBroadcasterTrait for EnhancedBitcoinTransactionBroadcaster {
    async fn new<S: BitcoinSigner + Send + Sync + Clone + 'static>(
        _btc_rpc: Arc<AsyncBitcoinClient>,
        _esplora_client: Arc<EsploraClient>,
        _btc_signer: S,
        _join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Self {
        panic!("EnhancedBitcoinTransactionBroadcaster requires a BitcoinDataEngine block subscription. Use with_config() instead.")
    }

    async fn broadcast_transaction(&self, tx_outs: &[TxOut]) -> eyre::Result<Txid> {
        let (response_tx, rx) = oneshot::channel();
        self.request_sender
            .send(Request {
                tx_outs: tx_outs.to_vec(),
                response_tx,
            })
            .await
            .map_err(|_| eyre::eyre!("queue error"))?;
        rx.await?
    }

    async fn can_fund_transaction(&self, tx_outs: &[TxOut]) -> eyre::Result<bool> {
        self.utxo_manager.can_fund_outputs(tx_outs).await
    }
}

impl EnhancedBitcoinTransactionBroadcaster {
    pub async fn with_config<S: BitcoinSigner + Send + Sync + Clone + 'static>(
        btc_rpc: Arc<AsyncBitcoinClient>,
        esplora_client: Arc<EsploraClient>,
        btc_signer: S,
        config: BroadcasterConfig,
        block_subscription: broadcast::Receiver<BlockLeaf>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Self {
        let utxo_config = UtxoManagerConfig {
            min_confirmations: config.min_utxo_confirmations,
            max_lock_time_seconds: 600, // 10 minutes
            spent_removal_confirmations: config.confirmation_threshold,
        };

        let utxo_manager = Arc::new(
            UtxoManager::new(
                config.db_location.clone(),
                utxo_config,
                btc_signer.get_script_pubkey(),
                btc_signer.get_address(),
            )
            .await
            .expect("Failed to create UTXO manager"),
        );

        // Create fee oracle
        let fee_oracle = Arc::new(BtcFeeOracle::new(config.esplora_api_url.clone()));

        // Spawn fee oracle updater
        fee_oracle.clone().spawn_updater_in_set(join_set);

        // Create transaction monitor
        let monitor_config = TransactionMonitorConfig {
            check_interval: config.monitoring_interval,
            max_transaction_age: 24 * 60 * 60, // 24 hours
            rbf_fee_increase_percent: 10,
            rbf_min_fee_increase_sats: 1000,
            rbf_target_percentile: 50,
            max_rbf_attempts: 3,
            rbf_retry_delay_seconds: 300, // 5 minutes
        };

        // Get a shared database connection for the monitor
        let db_conn = utxo_manager.get_shared_connection().await;

        let monitor = Arc::new(
            TransactionMonitor::new(
                db_conn,
                fee_oracle.clone(),
                monitor_config,
                utxo_manager.clone(),
                btc_rpc.clone(),
                Arc::new(btc_signer.clone()),
            )
            .expect("Failed to create transaction monitor with valid config"),
        );

        // Spawn the transaction monitor
        let monitor_clone = monitor.clone();
        let monitor_block_subscription = block_subscription.resubscribe();
        join_set.spawn(async move {
            monitor_clone
                .start(monitor_block_subscription, config.monitoring_interval)
                .await
        });

        // Create and spawn block watcher with subscription
        let block_watcher_config = BlockWatcherConfig {
            spent_removal_confirmations: config.confirmation_threshold,
            ..Default::default()
        };

        let block_watcher_db_conn = utxo_manager.get_shared_connection().await;
        let block_watcher = Arc::new(BlockWatcher::new(
            block_watcher_db_conn,
            utxo_manager.clone(),
            btc_rpc.clone(),
            block_watcher_config,
        ));

        // Spawn block watcher with subscription
        join_set.spawn(async move {
            block_watcher
                .start_with_subscription(block_subscription)
                .await
        });

        info!("Spawned monitoring tasks: fee oracle updater, transaction monitor, block watcher");

        // Create channel for requests
        let (request_sender, request_receiver) = channel(128);

        // Clone for the background task
        let utxo_manager_clone = utxo_manager.clone();
        let config_clone = config.clone();
        let fee_oracle_clone = fee_oracle.clone();

        // Spawn the enhanced broadcast queue consumer
        join_set.spawn(async move {
            consume_enhanced_broadcast_queue(
                btc_rpc,
                esplora_client,
                btc_signer,
                request_receiver,
                utxo_manager_clone,
                config_clone,
                fee_oracle_clone,
            )
            .await
        });

        Self {
            request_sender,
            utxo_manager,
            config,
            fee_oracle,
        }
    }

    /// Get the current UTXO balance
    pub async fn get_balance(&self) -> eyre::Result<(Amount, Amount)> {
        self.utxo_manager.get_balance().await
    }

    /// Sync UTXOs from the blockchain
    pub async fn sync_utxos(&self, esplora: &EsploraClient) -> eyre::Result<()> {
        let addr = self.utxo_manager.get_address();
        let utxos = esplora.get_address_utxo(&addr).await?;
        self.utxo_manager.sync_utxos_from_chain(&utxos).await
    }
}

async fn consume_enhanced_broadcast_queue<S: BitcoinSigner + Send + Sync + 'static>(
    btc_rpc: Arc<AsyncBitcoinClient>,
    esplora: Arc<EsploraClient>,
    signer: S,
    mut rx: Receiver<Request>,
    utxo_manager: Arc<UtxoManager>,
    config: BroadcasterConfig,
    fee_oracle: Arc<BtcFeeOracle>,
) -> eyre::Result<()> {
    let long_term_fee_rate = FeeRate::from_sat_per_vb(config.long_term_fee_rate_sat_vb).unwrap();

    // Initial UTXO sync
    let addr = signer.get_address();
    match esplora.get_address_utxo(&addr).await {
        Ok(utxos) => {
            if let Err(e) = utxo_manager.sync_utxos_from_chain(&utxos).await {
                warn!("Failed to sync UTXOs on startup: {}", e);
            }
        }
        Err(e) => warn!("Failed to fetch UTXOs on startup: {}", e),
    }

    while let Some(req) = rx.recv().await {
        let pay_outs = req.tx_outs.clone();
        let pay_value: Amount = pay_outs.iter().map(|o| o.value).sum();
        info!("New broadcast request for {} sats", pay_value.to_sat());

        // Get current fee rate using the fee oracle
        let fee_rate_sat_vb = match fee_oracle
            .get_fee_rate_by_percentile(config.target_fee_percentile)
            .await
        {
            rate if rate > 0 => FeeRate::from_sat_per_vb(rate).unwrap(),
            _ => {
                warn!("Fee oracle returned 0, using fallback");
                FeeRate::from_sat_per_vb(2).unwrap() // Conservative fallback
            }
        };

        debug!(
            "Using fee rate: {} sat/vB ({}th percentile)",
            fee_rate_sat_vb.to_sat_per_vb_ceil(),
            config.target_fee_percentile
        );

        // Select and lock UTXOs
        let (selected_utxos, change_amount) = match utxo_manager
            .select_and_lock_utxos(pay_value, fee_rate_sat_vb, long_term_fee_rate)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                let _ = req.response_tx.send(Err(e));
                continue;
            }
        };

        // Build transaction
        let mut outputs = pay_outs;
        let has_change = change_amount.is_some();
        if let Some(change_amt) = change_amount {
            outputs.push(TxOut {
                value: change_amt,
                script_pubkey: signer.get_script_pubkey(),
            });
        }

        let inputs: Vec<TxIn> = selected_utxos
            .iter()
            .map(|u| TxIn {
                previous_output: u.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xFFFFFFFD), // opt‑in RBF (BIP‑125)
                witness: Witness::new(),
            })
            .collect();

        let unsigned = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs.clone(), // Clone outputs so we can use it later
        };

        // Sign transaction
        let signed = match signer.sign_transaction(&unsigned, &selected_utxos) {
            Ok(tx) => tx,
            Err(e) => {
                // Unlock UTXOs on signing failure
                let outpoints: Vec<_> = selected_utxos.iter().map(|u| u.outpoint).collect();
                let _ = utxo_manager.unlock_utxos_by_outpoints(&outpoints).await;
                let _ = req.response_tx.send(Err(e));
                continue;
            }
        };

        let txid = signed.compute_txid();

        // Calculate actual fee
        let input_value: Amount = selected_utxos.iter().map(|u| u.value).sum();
        let output_value: Amount = signed.output.iter().map(|o| o.value).sum();
        let fee = input_value - output_value;
        let weight = signed.weight();
        let actual_fee_rate = fee.to_sat() as f64 / (weight.to_vbytes_ceil() as f64);

        // Broadcast transaction
        match btc_rpc.send_raw_transaction(&signed).await {
            Ok(_) => {
                info!(
                    "Broadcasted transaction {} with fee {} sats ({:.2} sat/vB)",
                    txid,
                    fee.to_sat(),
                    actual_fee_rate
                );

                // Mark UTXOs as spent
                let spent_pairs: Vec<_> =
                    selected_utxos.iter().map(|u| (u.outpoint, txid)).collect();
                let _ = utxo_manager.mark_spent(&spent_pairs).await;

                // Add change UTXO if created
                if has_change {
                    let change_idx = (outputs.len() - 1) as u32;
                    let change_outpoint = OutPoint::new(txid, change_idx);
                    if let Some(change_amt) = change_amount {
                        let _ = utxo_manager
                            .add_new_utxo(change_outpoint, change_amt, signer.get_script_pubkey())
                            .await;
                    }
                }

                // Store transaction in database
                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if let Ok(conn) = utxo_manager.get_connection().await {
                    let _ = add_broadcasted_transaction(
                        &*conn,
                        &signed,
                        fee,
                        actual_fee_rate,
                        None, // No RBF replacement yet
                        current_time,
                    )
                    .await;

                    // Track parent-child relationships
                    let relationships = find_tx_relationships(&signed, &selected_utxos);
                    if !relationships.is_empty() {
                        let _ = add_tx_relationships(&*conn, &relationships).await;
                    }
                }

                let _ = req.response_tx.send(Ok(txid));
            }
            Err(e) => {
                warn!("Failed to broadcast transaction: {}", e);
                // Unlock UTXOs on broadcast failure
                let outpoints: Vec<_> = selected_utxos.iter().map(|u| u.outpoint).collect();
                let _ = utxo_manager.unlock_utxos_by_outpoints(&outpoints).await;
                let _ = req
                    .response_tx
                    .send(Err(eyre::eyre!("Broadcast failed: {}", e)));
            }
        }
    }
    Ok(())
}

fn find_tx_relationships(
    tx: &Transaction,
    selected_utxos: &[InputUtxo],
) -> Vec<(Txid, Txid, usize)> {
    let mut relationships = Vec::new();
    let child_txid = tx.compute_txid();

    // Check each input to see if it's from an unconfirmed transaction
    for (idx, input) in tx.input.iter().enumerate() {
        // The parent txid is in the input's previous_output
        let parent_txid = input.previous_output.txid;

        // Skip if this is from a coinbase transaction (null outpoint)
        if input.previous_output.is_null() {
            continue;
        }

        // Check if this UTXO was from a recent transaction, so prolly unconfirmed
        // Can't tell forsure if it's unconfirmed without a database query,
        // but we can record all relationships and let the analyzer filter later
        if selected_utxos
            .iter()
            .any(|u| u.outpoint == input.previous_output)
        {
            relationships.push((parent_txid, child_txid, idx));
        }
    }

    if !relationships.is_empty() {
        debug!(
            "Found {} potential parent-child relationships for transaction {}",
            relationships.len(),
            child_txid
        );
    }

    relationships
}
