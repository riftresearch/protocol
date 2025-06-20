use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::primitives::Address;
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::{Filter, Log};
use alloy_sol_types::SolEvent;
use eyre::Result;
use log::info;
use rift_sdk::{btc_txn_broadcaster::SimpleBitcoinTransactionBroadcaster, DatabaseLocation};
use rift_sdk::btc_txn_broadcaster::BitcoinTransactionBroadcasterTrait;
use rift_sdk::bitcoin_utils::AsyncBitcoinClient;
use rift_core::order_hasher::SolidityHash;
use sol_bindings::{Order, OrderCreated};
use tokio::{
    sync::{mpsc, Mutex},
    task::JoinSet,
};
use tokio_rusqlite::Connection;
use tokio_util::time::DelayQueue;
use bitcoincore_rpc_async::{bitcoin::Txid, RpcApi};
use bitcoin_data_engine::BitcoinDataEngine;

use crate::db::{
    is_order_already_processed,
    setup_order_filler_database, store_processed_order,
    update_order_status, ORDER_STATUS_CONFIRMED, ORDER_STATUS_FAILED,
    ORDER_STATUS_SENT,
};
use crate::tokenized_btc_redeemer::RedemptionTrigger;

#[derive(Clone)]
pub struct OrderFillerConfig {
    pub market_maker_address: Address,
    pub rift_exchange_address: Address,
    pub delay_seconds: u64,
    pub max_batch_size: usize,
    pub database_location: DatabaseLocation,
    pub required_confirmations: u32,
    pub confirmation_timeout: u64,
}

impl Default for OrderFillerConfig {
    fn default() -> Self {
        Self {
            market_maker_address: Address::ZERO,
            rift_exchange_address: Address::ZERO,
            delay_seconds: 30,
            max_batch_size: 10,
            database_location: DatabaseLocation::InMemory,
            required_confirmations: 6,
            confirmation_timeout: 86400,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingOrder {
    pub order: Order,
    pub received_at: Instant,
    pub process_at: Instant,
}

impl PendingOrder {
    pub fn new(order: Order, delay_duration: Duration) -> Self {
        let now = Instant::now();
        Self {
            order,
            received_at: now,
            process_at: now + delay_duration,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingTransaction {
    pub txid: Txid,
    pub orders: Vec<Order>,
    pub broadcast_time: Instant,
    pub confirmations: u32,
    pub is_confirmed: bool,
    pub last_checked: Instant,
}

#[derive(Debug, Clone)]
pub enum TransactionStatus {
    Confirmed,
    Pending(u32),
    TimedOut,
    Failed(String),
}

pub struct OrderFiller {
    config: OrderFillerConfig,
    bitcoin_broadcaster: Arc<SimpleBitcoinTransactionBroadcaster>,
    bitcoin_rpc: Arc<AsyncBitcoinClient>,
    bitcoin_data_engine: Arc<BitcoinDataEngine>,
    delay_queue: Arc<Mutex<DelayQueue<PendingOrder>>>,
    processed_orders_db: Arc<Connection>,
    pending_transactions: Arc<Mutex<HashMap<Txid, PendingTransaction>>>,
    redeemer_trigger_sender: Option<mpsc::Sender<RedemptionTrigger>>,
}

impl OrderFiller {
    pub fn new(
        config: OrderFillerConfig,
        bitcoin_broadcaster: Arc<SimpleBitcoinTransactionBroadcaster>,
        bitcoin_rpc: Arc<AsyncBitcoinClient>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        processed_orders_db: Arc<Connection>,
        redeemer_trigger_sender: Option<mpsc::Sender<RedemptionTrigger>>,
    ) -> Self {
        Self {
            config,
            bitcoin_broadcaster,
            bitcoin_rpc,
            bitcoin_data_engine,
            delay_queue: Arc::new(Mutex::new(DelayQueue::new())),
            processed_orders_db,
            pending_transactions: Arc::new(Mutex::new(HashMap::new())),
            redeemer_trigger_sender,
        }
    }

    pub async fn run(
        provider: DynProvider,
        config: OrderFillerConfig,
        bitcoin_broadcaster: Arc<SimpleBitcoinTransactionBroadcaster>,
        bitcoin_rpc: Arc<AsyncBitcoinClient>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        processed_orders_db: Arc<Connection>,
        redeemer_trigger_sender: Option<mpsc::Sender<RedemptionTrigger>>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<()> {
        info!(
            "Starting OrderFiller with config: market_maker={}, delay={}s, batch_size={}",
            config.market_maker_address, config.delay_seconds, config.max_batch_size
        );


        setup_order_filler_database(&processed_orders_db).await?;
        info!("OrderFiller database schema initialized");


        let order_filler = Arc::new(Self::new(
            config.clone(),
            bitcoin_broadcaster,
            bitcoin_rpc,
            bitcoin_data_engine,
            processed_orders_db,
            redeemer_trigger_sender,
        ));


        let (order_tx, order_rx) = mpsc::channel(100);
        let (ready_order_tx, ready_order_rx) = mpsc::channel(100);


        Self::spawn_event_listener(
            provider,
            config.clone(),
            order_tx,
            order_filler.processed_orders_db.clone(),
            join_set,
        )
        .await?;

        Self::spawn_delay_queue_processor(
            order_rx,
            order_filler.delay_queue.clone(),
            ready_order_tx,
            config.clone(),
            join_set,
        )
        .await?;

        Self::spawn_confirmation_monitor(order_filler.clone(), join_set).await?;

        Self::spawn_payment_processor(order_filler.clone(), ready_order_rx, join_set).await?;

        info!("OrderFiller started successfully");
        Ok(())
    }

    async fn spawn_event_listener(
        provider: DynProvider,
        config: OrderFillerConfig,
        order_tx: mpsc::Sender<Order>,
        processed_orders_db: Arc<Connection>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<()> {
        join_set.spawn(async move {
            info!("Event listener task started");


            let filter = Filter::new()
                .address(config.rift_exchange_address)
                .event(OrderCreated::SIGNATURE);


            let mut subscription = match provider.subscribe_logs(&filter).await {
                Ok(sub) => {
                    info!(
                        "Successfully subscribed to OrderCreated events from {}",
                        config.rift_exchange_address
                    );
                    sub
                }
                Err(e) => {
                    log::error!("Failed to subscribe to OrderCreated events: {:?}", e);
                    return Err(eyre::eyre!("Event listener task failed: {}", e));
                }
            };


            loop {
                match subscription.recv().await {
                    Ok(log) => {
                        log::debug!("Received new OrderCreated event");
                        if let Err(e) = Self::process_order_created_event(
                            &log,
                            &config,
                            &order_tx,
                            &processed_orders_db,
                        )
                        .await
                        {
                            log::error!("Error processing OrderCreated event: {:?}", e);
                        }
                    }
                    Err(e) => {
                        log::error!("Error receiving log: {:?}", e);

                        tokio::time::sleep(Duration::from_secs(5)).await;
                        break;
                    }
                }
            }

            log::warn!("Event listener task exiting, attempting to restart...");
            Ok(())
        });
        Ok(())
    }

    async fn process_order_created_event(
        log: &Log,
        config: &OrderFillerConfig,
        order_tx: &mpsc::Sender<Order>,
        processed_orders_db: &Connection,
    ) -> Result<()> {

        let decoded = OrderCreated::decode_log(&log.inner)
            .map_err(|e| eyre::eyre!("Failed to decode OrderCreated event: {:?}", e))?;

        let order = decoded.data.order;

        info!("Processing OrderCreated event for order #{}", order.index);

        if !Self::validate_order_for_processing(&order, config, processed_orders_db).await? {
            log::debug!("Order #{} failed validation, skipping", order.index);
            return Ok(());
        }

        if let Err(e) = order_tx.send(order.clone()).await {
            log::error!(
                "Failed to send order #{} to delay queue processor: {:?}",
                order.index,
                e
            );
            return Err(eyre::eyre!(
                "Failed to send order to delay queue processor: {}",
                e
            ));
        }

        info!("Successfully queued order #{} for processing", order.index);
        Ok(())
    }

    pub fn is_order_for_market_maker(order: &Order, config: &OrderFillerConfig) -> bool {
        order.designatedReceiver == config.market_maker_address
    }

    async fn spawn_delay_queue_processor(
        mut order_rx: mpsc::Receiver<Order>,
        delay_queue: Arc<Mutex<DelayQueue<PendingOrder>>>,
        ready_order_tx: mpsc::Sender<PendingOrder>,
        config: OrderFillerConfig,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<()> {
        join_set.spawn(async move {
            info!("delay queue processor task started");
            
            let delay_duration = Duration::from_secs(config.delay_seconds);
            info!("Processing orders with {}s delay", config.delay_seconds);

            while let Some(order) = order_rx.recv().await {
                info!("Received order #{} for delay queue processing", order.index);
                
                let pending_order = PendingOrder::new(order.clone(), delay_duration);

                let ready_tx = ready_order_tx.clone();
                let order_clone = pending_order.clone();
                
                tokio::spawn(async move {

                    tokio::time::sleep(delay_duration).await;
                    
                    info!("Order #{} delay expired, sending to payment processor", order_clone.order.index);

                    if let Err(e) = ready_tx.send(order_clone).await {
                        log::error!("Failed to send ready order #{} to payment processor: {:?}", 
                                   order.index, e);
                    }
                });
                
                let mut queue = delay_queue.lock().await;
                let _key = queue.insert(pending_order.clone(), delay_duration);
                info!(
                    "Added order #{} to delay queue. Will process in {:?}",
                    order.index,
                    delay_duration
                );
            }
            
            info!("Delay queue processor task exiting - order channel closed");
            Ok(())
        });
        Ok(())
    }

    async fn spawn_confirmation_monitor(
        order_filler: Arc<Self>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<()> {
        join_set.spawn(async move {
            info!("confirmation monitor task started");
            
            let config = order_filler.config.clone();
            let bitcoin_rpc = order_filler.bitcoin_rpc.clone();
            let bitcoin_data_engine = order_filler.bitcoin_data_engine.clone();
            let pending_transactions = order_filler.pending_transactions.clone();
            let processed_orders_db = order_filler.processed_orders_db.clone();
            
            let required_confirmations = config.required_confirmations;
            let confirmation_timeout = Duration::from_secs(config.confirmation_timeout);

            info!(
                "confirmation monitor configured: {} confirmations required, timeout after {}s",
                required_confirmations, config.confirmation_timeout
            );

            let mut block_subscription = bitcoin_data_engine.subscribe_to_new_blocks();
            
            info!("Subscribed to Bitcoin block events for confirmation monitoring");

            Self::check_all_pending_confirmations(
                &bitcoin_rpc,
                &pending_transactions,
                &processed_orders_db,
                required_confirmations,
                confirmation_timeout,
            ).await?;

            loop {
                match block_subscription.recv().await {
                    Ok(new_block) => {
                        info!("Bitcoin block received (height: {}), checking pending transaction confirmations", 
                              new_block.height);

                        match Self::check_all_pending_confirmations(
                            &bitcoin_rpc,
                            &pending_transactions,
                            &processed_orders_db,
                            required_confirmations,
                            confirmation_timeout,
                        ).await {
                            Ok(checked_count) => {
                                if checked_count > 0 {
                                    info!("Checked {} pending transactions after new block", checked_count);
                                }
                            }
                            Err(e) => {
                                log::error!("Error checking confirmations after new block: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Error receiving Bitcoin block event: {:?}", e);

                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });
        Ok(())
    }

    async fn check_all_pending_confirmations(
        bitcoin_rpc: &Arc<AsyncBitcoinClient>,
        pending_transactions: &Arc<Mutex<HashMap<Txid, PendingTransaction>>>,
        processed_orders_db: &Arc<Connection>,
        required_confirmations: u32,
        confirmation_timeout: Duration,
    ) -> Result<usize> {

        let pending_txids: Vec<Txid> = {
            let transactions = pending_transactions.lock().await;
            transactions.keys().cloned().collect()
        };

        let checked_count = pending_txids.len();
        
        for txid in pending_txids {
            match Self::check_and_update_transaction_status(
                &txid,
                bitcoin_rpc,
                pending_transactions,
                processed_orders_db,
                required_confirmations,
                confirmation_timeout,
            ).await {
                Ok(status) => {
                    match status {
                        TransactionStatus::Confirmed => {
                            info!("Transaction {} confirmed with {} confirmations", txid, required_confirmations);
                        }
                        TransactionStatus::Pending(confirmations) => {
                            log::debug!("Transaction {} has {} confirmations (need {})", 
                                       txid, confirmations, required_confirmations);
                        }
                        TransactionStatus::TimedOut => {
                            log::warn!("Transaction {} timed out waiting for confirmations", txid);
                        }
                        TransactionStatus::Failed(reason) => {
                            log::error!("Transaction {} failed: {}", txid, reason);
                        }
                    }
                }
                Err(e) => {
                    log::error!("Error checking transaction {}: {:?}", txid, e);
                }
            }
        }

        Ok(checked_count)
    }

    async fn check_and_update_transaction_status(
        txid: &Txid,
        bitcoin_rpc: &Arc<AsyncBitcoinClient>,
        pending_transactions: &Arc<Mutex<HashMap<Txid, PendingTransaction>>>,
        processed_orders_db: &Arc<Connection>,
        required_confirmations: u32,
        confirmation_timeout: Duration,
    ) -> Result<TransactionStatus> {

        let tx_result = match bitcoin_rpc.get_raw_transaction_info(txid, None).await {
            Ok(result) => result,
            Err(e) => {
                log::error!("Failed to get transaction info for {}: {:?}", txid, e);
                return Ok(TransactionStatus::Failed(format!("RPC error: {}", e)));
            }
        };

        let confirmations = tx_result.confirmations.unwrap_or(0);
        
        let pending_tx = {
            let mut transactions = pending_transactions.lock().await;
            match transactions.get_mut(txid) {
                Some(tx) => {
                    tx.confirmations = confirmations;
                    tx.last_checked = Instant::now();
                    tx.clone()
                }
                None => {

                    return Ok(TransactionStatus::Failed("Transaction not found in pending list".to_string()));
                }
            }
        };

        if confirmations >= required_confirmations {

            for order in &pending_tx.orders {
                if let Err(e) = update_order_status(
                    processed_orders_db,
                    &hex::encode(order.hash()),
                    ORDER_STATUS_CONFIRMED,
                    None,
                ).await {
                    log::error!("Failed to update order #{} status to confirmed: {:?}", order.index, e);
                } else {
                    info!("Updated order #{} status to confirmed (txid: {})", order.index, txid);
                }
            }

            pending_transactions.lock().await.remove(txid);
            return Ok(TransactionStatus::Confirmed);
        }


        if pending_tx.broadcast_time.elapsed() > confirmation_timeout {

            for order in &pending_tx.orders {
                if let Err(e) = update_order_status(
                    processed_orders_db,
                    &hex::encode(order.hash()),
                    ORDER_STATUS_FAILED,
                    Some("Confirmation timeout"),
                ).await {
                    log::error!("Failed to update order #{} status to failed: {:?}", order.index, e);
                } else {
                    log::warn!("Updated order #{} status to failed due to confirmation timeout (txid: {})", 
                              order.index, txid);
                }
            }

            pending_transactions.lock().await.remove(txid);
            return Ok(TransactionStatus::TimedOut);
        }

        Ok(TransactionStatus::Pending(confirmations))
    }

    async fn spawn_payment_processor(
        order_filler: Arc<Self>,
        mut ready_order_rx: mpsc::Receiver<PendingOrder>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<()> {
        join_set.spawn(async move {
            info!("Payment processor task started");
            
            let max_batch_size = order_filler.config.max_batch_size;
            let mut batch = Vec::new();
            let batch_timeout = Duration::from_secs(30);
            
            info!("Payment processor waiting for ready orders (max batch size: {}, timeout: {:?})", 
                  max_batch_size, batch_timeout);

            loop {
                tokio::select! {

                    maybe_order = ready_order_rx.recv() => {
                        match maybe_order {
                            Some(pending_order) => {
                                info!("Received ready order #{} for processing", pending_order.order.index);
                                batch.push(pending_order);
                                

                                if batch.len() >= max_batch_size {
                                    info!("Processing full batch of {} ready orders", batch.len());
                                    
                                    if let Err(e) = order_filler.process_order_batch(batch.clone()).await {
                                        log::error!("Error processing order batch: {:?}", e);
                                    }
                                    
                                    batch.clear();
                                }
                            }
                            None => {

                                if !batch.is_empty() {
                                    info!("Processing final batch of {} ready orders", batch.len());
                                    if let Err(e) = order_filler.process_order_batch(batch).await {
                                        log::error!("Error processing final order batch: {:?}", e);
                                    }
                                }
                                break;
                            }
                        }
                    }
                    
                    _ = tokio::time::sleep(batch_timeout) => {
                        if !batch.is_empty() {
                            info!("Processing timeout batch of {} ready orders", batch.len());
                            
                            if let Err(e) = order_filler.process_order_batch(batch.clone()).await {
                                log::error!("Error processing timeout batch: {:?}", e);
                            }
                            
                            batch.clear();
                        }
                    }
                }
            }
            
            info!("Payment processor task exiting - ready order channel closed");
            Ok(())
        });
        Ok(())
    }

    pub async fn validate_order_for_processing(
        order: &Order,
        config: &OrderFillerConfig,
        processed_orders_db: &Connection,
    ) -> Result<bool> {

        if !Self::is_order_for_market_maker(order, config) {
            return Ok(false);
        }

        if is_order_already_processed(processed_orders_db, order).await? {
            info!("Order #{} already processed, skipping", order.index);
            return Ok(false);
        }

        info!("Order #{} validated for processing", order.index);
        Ok(true)
    }

    async fn process_order_batch(&self, orders: Vec<PendingOrder>) -> Result<()> {
        if orders.is_empty() {
            return Ok(());
        }

        info!("Processing batch of {} orders", orders.len());

        let order_structs: Vec<Order> = orders.iter().map(|po| po.order.clone()).collect();
        let total_order_amount: u64 = order_structs.iter().map(|order| order.expectedSats).sum();
        
        info!(
            "Batch requires {} sats for {} orders",
            total_order_amount, orders.len()
        );

        let tx_outputs = rift_sdk::txn_builder::get_outputs_for_orders(&order_structs);
        
        info!("Created {} transaction outputs for batch", tx_outputs.len());

        match self.bitcoin_broadcaster.broadcast_transaction(&tx_outputs).await {
            Ok(broadcast_txid) => {
                info!("Successfully broadcast transaction {} for {} orders", broadcast_txid, orders.len());
                
                for pending_order in &orders {
                    if let Err(e) = store_processed_order(
                        &self.processed_orders_db,
                        &pending_order.order,
                        &broadcast_txid.to_string(),
                        ORDER_STATUS_SENT,
                    ).await {
                        log::error!("Failed to store processed order #{}: {:?}", pending_order.order.index, e);
                    } else {
                        info!("Stored order #{} as sent with txid {}", pending_order.order.index, broadcast_txid);
                    }
                }
                
                let pending_transaction = PendingTransaction {
                    txid: broadcast_txid,
                    orders: order_structs.clone(),
                    broadcast_time: Instant::now(),
                    confirmations: 0,
                    is_confirmed: false,
                    last_checked: Instant::now(),
                };
                
                
                let mut pending_txs = self.pending_transactions.lock().await;
                pending_txs.insert(broadcast_txid, pending_transaction);
                info!("Added transaction {} to confirmation monitoring (tracking {} transactions)", 
                        broadcast_txid, pending_txs.len());
                
                if let Some(ref trigger_sender) = self.redeemer_trigger_sender {
                    let total_cbbtc_amount: u64 = order_structs.iter()
                        .map(|order| {
                            order.amount.try_into().unwrap_or(u64::MAX)
                        })
                        .sum();
                    
                    if total_cbbtc_amount > 0 {
                        info!("Triggering cbBTC redemption for {} sats from {} orders", 
                              total_cbbtc_amount, order_structs.len());
                        
                        if let Err(e) = crate::tokenized_btc_redeemer::trigger_redemption_on_order_settled(
                            trigger_sender.clone(),
                            total_cbbtc_amount,
                            format!("batch_tx_{}", broadcast_txid),
                        ).await {
                            log::error!("Failed to trigger cbBTC redemption: {:?}", e);
                        } else {
                            info!("Successfully triggered cbBTC redemption check");
                        }
                    }
                }
                
                Ok(())
            }
            Err(e) => {
                log::error!("Failed to broadcast transaction for {} orders: {:?}", orders.len(), e);
                
                let error_reason = if e.to_string().contains("insufficient") {
                    "insufficient_btc_funds"
                } else {
                    "broadcast_failed"
                };
                
                for pending_order in &orders {
                    if let Err(store_err) = store_processed_order(
                        &self.processed_orders_db,
                        &pending_order.order,
                        error_reason,
                        ORDER_STATUS_FAILED,
                    ).await {
                        log::error!("Failed to store failed order #{}: {:?}", pending_order.order.index, store_err);
                    } else {
                        log::warn!("Stored order #{} as failed due to: {}", pending_order.order.index, error_reason);
                    }
                }
                
                Err(eyre::eyre!("Failed to broadcast transaction: {}", e))
            }
        }
    }

    pub async fn update_order_status_external(
        &self,
        order_hash: &str,
        new_status: &str,
        error_message: Option<&str>,
    ) -> Result<()> {
        update_order_status(
            &self.processed_orders_db,
            order_hash,
            new_status,
            error_message,
        )
        .await
    }

    pub async fn get_pending_transaction(&self, txid: &Txid) -> Option<PendingTransaction> {
        let pending_txs = self.pending_transactions.lock().await;
        pending_txs.get(txid).cloned()
    }

    pub async fn remove_pending_transaction(&self, txid: &Txid) -> Option<PendingTransaction> {
        let mut pending_txs = self.pending_transactions.lock().await;
        pending_txs.remove(txid)
    }
}
