mod mempool_electrs;
use crate::mempool_electrs::MempoolElectrsClient;
use alloy::consensus::BlockHeader;
use alloy::eips::BlockId;
use alloy::network::BlockResponse;
use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::pubsub::PubSubFrontend;
use alloy::rpc::types::BlockTransactionsKind;
use alloy::sol_types::SolValue;
use bitcoincore_rpc_async::RpcApi;
use clap::Parser;
use data_engine::engine::ContractDataEngine;
use eyre::{eyre, Result};
use mempool_electrs::{TxStatus, Utxo};
use rift_core::vaults::hash_deposit_vault;
use rift_sdk::{
    bitcoin_utils::AsyncBitcoinClient,
    create_websocket_provider,
    txn_builder::{build_rift_payment_transaction, P2WPKHBitcoinWallet},
    DatabaseLocation,
};
use sol_bindings::Types::DepositVault;
use std::{cmp::Reverse, path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_rusqlite::{params, Connection};
use tracing::{error, info};

#[derive(Parser, Debug, Clone)]
pub struct MakerConfig {
    /// EVM WebSocket provider URL
    #[arg(long, env = "EVM_WS_URL")]
    evm_ws_url: String,

    /// Rift contract address
    #[arg(long, env = "RIFT_CONTRACT_ADDRESS")]
    rift_contract_address: String,

    /// Rift deployment block number
    #[arg(long, env = "RIFT_DEPLOYMENT_BLOCK_NUMBER")]
    rift_deployment_block_number: u64,

    /// Mempool Electrs URL
    #[arg(long, env = "MEMPOOL_ELECTRS_URL")]
    mempool_electrs_url: String,

    /// Bitcoin Core RPC URL
    #[arg(long, env = "BTC_RPC_URL")]
    btc_rpc_url: String,

    /// Bitcoin Core RPC User
    #[arg(long, env = "BTC_RPC_USER")]
    btc_rpc_user: String,

    /// Bitcoin Core RPC Password
    #[arg(long, env = "BTC_RPC_PASS")]
    btc_rpc_pass: String,

    /// Market Maker's Bitcoin Mnemonic
    #[arg(long, env = "BTC_MNEMONIC")]
    btc_mnemonic: String,

    /// Market Maker's Ethereum Address
    #[arg(long, env = "ETH_ADDRESS")]
    eth_address: String,

    /// Database location for local SQLite database
    #[arg(long, env = "DB_LOCATION")]
    db_location: DatabaseLocation,

    /// Polling interval in seconds
    #[arg(long, env = "POLL_INTERVAL", default_value = "1")]
    poll_interval: u64,

    /// Fee amount in satoshis for swap transactions
    #[arg(long, env = "FEE_SATS", default_value = "2000")]
    fee_sats: u64,

    /// Checkpoint leaves
    #[arg(long)]
    checkpoint_file: String,
}

/// Represents a swap in our local database
#[derive(Debug)]
struct ProcessedSwap {
    deposit_commitment: String,
    txid: String,
    amount_sats: u64,
    timestamp: i64,
}

/// Main market maker structure
struct MarketMaker {
    payment_database_connection: Arc<Connection>,
    bitcoin_client: Arc<AsyncBitcoinClient>,
    wallet: P2WPKHBitcoinWallet,
    eth_address: Address,
    data_engine: ContractDataEngine,
    config: MakerConfig,
    mempool_electrs_client: Arc<MempoolElectrsClient>,
    provider: Arc<dyn Provider<PubSubFrontend>>,
    mempool_utxo: Option<Utxo>,
}

fn get_qualified_payment_database_path(database_location: String) -> String {
    let path = PathBuf::from(database_location);
    let payment_db_path = path.join("payment.db");
    payment_db_path.to_str().expect("Invalid path").to_string()
}

const LOCKUP_PERIOD: u64 = 2 * 60 * 60; // 2 hours

impl MarketMaker {
    /// Create a new market maker instance
    async fn new(config: MakerConfig) -> Result<Self> {
        let cc_config = config.clone();
        let payment_database_connection = Arc::new(match &config.db_location {
            DatabaseLocation::InMemory => tokio_rusqlite::Connection::open_in_memory().await?,
            DatabaseLocation::Directory(path) => {
                tokio_rusqlite::Connection::open(get_qualified_payment_database_path(
                    path.to_string(),
                ))
                .await?
            }
        });
        let mempool_electrs_client =
            Arc::new(MempoolElectrsClient::new(&config.mempool_electrs_url));

        let provider: Arc<dyn Provider<PubSubFrontend>> =
            Arc::new(create_websocket_provider(&config.evm_ws_url).await?);
        let checkpoint_leaves =
            checkpoint_downloader::decompress_checkpoint_file(&config.checkpoint_file).unwrap();
        let mut join_set = JoinSet::new();
        let rift_exchange_address = Address::from_str(&config.rift_contract_address)
            .map_err(|e| eyre!("Invalid Rift contract address: {}", e))?;

        let data_engine = ContractDataEngine::start(
            &config.db_location,
            provider.clone(),
            rift_exchange_address,
            config.rift_deployment_block_number,
            checkpoint_leaves,
            &mut join_set,
        )
        .await?;

        // Initialize the database table
        payment_database_connection
            .call(|conn| {
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS processed_swaps (
                    deposit_commitment TEXT PRIMARY KEY,
                    txid TEXT NOT NULL,
                    amount_sats INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL
                )",
                    [],
                )?;
                Ok::<_, tokio_rusqlite::Error>(())
            })
            .await?;

        // Create HTTP client for data engine

        // Initialize Bitcoin client
        let bitcoin_client = Arc::new(
            rift_sdk::bitcoin_utils::AsyncBitcoinClient::new(
                config.btc_rpc_url.clone(),
                bitcoincore_rpc_async::Auth::UserPass(
                    config.btc_rpc_user.clone(),
                    config.btc_rpc_pass.clone(),
                ),
                Duration::from_secs(10),
            )
            .await?,
        );

        // Initialize wallet from mnemonic
        let wallet = P2WPKHBitcoinWallet::from_mnemonic(
            &config.btc_mnemonic,
            None,
            bitcoin::Network::Bitcoin,
            None,
        )?;
        println!("Wallet: {:?}", wallet);

        // Parse ETH address
        let eth_address = Address::from_str(&config.eth_address)
            .map_err(|e| eyre!("Invalid Ethereum address: {}", e))?;

        Ok(Self {
            payment_database_connection,
            bitcoin_client,
            wallet,
            eth_address,
            data_engine,
            config: cc_config,
            mempool_electrs_client,
            provider,
            mempool_utxo: None,
        })
    }

    /// Run the market maker loop
    async fn run(&mut self) -> Result<()> {
        info!("Starting market maker with address: {}", self.eth_address);
        info!("Bitcoin wallet address: {}", self.wallet.address);

        loop {
            match self.process_fillable_swaps().await {
                Ok(count) => {
                    info!("Processed {} fillable swaps", count);
                }
                Err(e) => {
                    error!("Error processing swaps: {}", e);
                }
            }

            sleep(Duration::from_secs(self.config.poll_interval)).await;
        }
    }

    /// Process fillable swaps
    async fn process_fillable_swaps(&mut self) -> Result<usize> {
        // 1. Fetch deposits from the data engine
        let fillable_deposits = self.fetch_fillable_deposits().await?;
        if fillable_deposits.is_empty() {
            info!("No fillable deposits found");
            return Ok(0);
        }

        info!(
            "Found {} potential deposits to fill",
            fillable_deposits.len()
        );

        // 2. Filter out already processed deposits
        let unprocessed_deposits = self.filter_processed_deposits(fillable_deposits).await?;
        if unprocessed_deposits.is_empty() {
            info!("All deposits have been already processed");
            return Ok(0);
        }

        info!(
            "{} deposits remain after filtering already processed ones",
            unprocessed_deposits.len()
        );

        // 3. Process each unprocessed deposit
        let mut processed_count = 0;
        for deposit in unprocessed_deposits {
            match self.process_deposit(deposit).await {
                Ok(_) => {
                    processed_count += 1;
                }
                Err(e) => {
                    error!("Failed to process deposit: {}", e);
                }
            }
        }

        Ok(processed_count)
    }

    /// Fetch fillable deposits from the data engine
    async fn fetch_fillable_deposits(&self) -> Result<Vec<DepositVault>> {
        // TODO: Track the block number of the last deposit processed
        let deposits = self
            .data_engine
            .get_deposits_for_recipient(self.eth_address, self.config.rift_deployment_block_number)
            .await?;

        info!("Found {} fillable deposits", deposits.len());

        Ok(deposits)
    }

    /// Filter out deposits that we've already processed
    async fn filter_processed_deposits(
        &self,
        deposits: Vec<DepositVault>,
    ) -> Result<Vec<DepositVault>> {
        let mut unprocessed = Vec::new();

        let latest_block = self
            .provider
            .get_block(BlockId::latest(), BlockTransactionsKind::Hashes)
            .await?;

        let latest_block_timestamp = latest_block.unwrap().header().timestamp();

        for deposit in deposits {
            let commitment = format!("0x{}", hex::encode(hash_deposit_vault(&deposit)));

            let already_processed = self
                .payment_database_connection
                .call(move |conn| {
                    let mut stmt = conn.prepare(
                        "SELECT COUNT(*) FROM processed_swaps WHERE deposit_commitment = ?1",
                    )?;

                    let count: i64 = stmt.query_row(params![commitment], |row| row.get(0))?;

                    if latest_block_timestamp
                        > deposit.depositTimestamp
                            + (LOCKUP_PERIOD * deposit.confirmationBlocks as u64)
                    {
                        println!("Deposit has expired: {}", deposit.vaultIndex);
                        return Ok(true);
                    }

                    if count > 0 {
                        println!("Deposit has already been processed: {}", deposit.vaultIndex);
                    }

                    let ignored_deposits: Vec<u32> = (16..=27).collect();

                    if ignored_deposits
                        .contains(&u32::try_from(deposit.vaultIndex).unwrap_or_default())
                    {
                        println!("Deposit is manually ignored: {}", deposit.vaultIndex);
                        return Ok(true);
                    }

                    Ok::<_, tokio_rusqlite::Error>(count > 0)
                })
                .await?;

            if !already_processed {
                unprocessed.push(deposit);
            }
        }

        Ok(unprocessed)
    }

    /// Process a single deposit by creating and sending a Bitcoin transaction
    async fn process_deposit(&mut self, deposit: DepositVault) -> Result<()> {
        info!(
            "Processing deposit with expected sats: {}",
            deposit.expectedSats
        );

        // Find a suitable UTXO
        let utxos = if let Some(utxo) = self.mempool_utxo.clone() {
            println!("Using calculated mempool UTXO");
            vec![utxo]
        } else {
            println!("Finding suitable UTXOs");
            self.find_suitable_utxos(deposit.expectedSats + self.config.fee_sats)
                .await?
        };

        if utxos.is_empty() {
            return Err(eyre!("No suitable UTXOs found"));
        }

        // Use the first available UTXO
        let utxo = &utxos[0];

        info!(
            "Using UTXO {}:{} with amount {} sats",
            utxo.txid, utxo.vout, utxo.value
        );

        let txid = bitcoincore_rpc_async::bitcoin::Txid::from_str(&utxo.txid).unwrap();

        let tx = self.bitcoin_client.get_raw_transaction(&txid, None).await?;

        let canon_txid: bitcoin::Txid = bitcoin::consensus::deserialize(
            &bitcoincore_rpc_async::bitcoin::consensus::serialize(&txid),
        )
        .unwrap();

        let canon_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &bitcoincore_rpc_async::bitcoin::consensus::serialize(&tx),
        )
        .unwrap();

        // Build the transaction paying to the deposit's scriptPubKey
        let payment_tx = build_rift_payment_transaction(
            &deposit,
            &canon_txid,
            &canon_tx,
            utxo.vout,
            &self.wallet,
            self.config.fee_sats,
        )?;

        // Send the transaction
        let raw_tx = bitcoin::consensus::serialize(&payment_tx);
        let tx_result = self.bitcoin_client.send_raw_transaction(&raw_tx).await?;

        info!("Transaction sent with txid: {}", tx_result);

        // Record the transaction in our database
        let commitment = format!("0x{}", hex::encode(hash_deposit_vault(&deposit)));
        let tx_hex = tx_result.to_string();
        let now = chrono::Utc::now().timestamp();

        let cc_commitment = commitment.clone();
        let cc_tx_hex = tx_hex.clone();
        self.payment_database_connection
            .call(move |conn| {
                conn.execute(
                "INSERT INTO processed_swaps (deposit_commitment, txid, amount_sats, timestamp) 
                 VALUES (?1, ?2, ?3, ?4)",
                params![commitment.clone(), cc_tx_hex, deposit.expectedSats, now],
            )?;
                Ok::<_, tokio_rusqlite::Error>(())
            })
            .await?;

        self.mempool_utxo = Some(Utxo {
            txid: tx_hex,
            vout: 2,
            // set this to comically high value to indicate that it's a mempool UTXO
            value: u64::MAX - 1,
            status: TxStatus {
                confirmed: false,
                block_height: 0,
                block_hash: String::new(),
                block_time: 0,
            },
        });

        info!(
            "Recorded transaction for deposit commitment {}",
            cc_commitment
        );

        Ok(())
    }

    /// Find suitable UTXOs for a transaction
    async fn find_suitable_utxos(&self, required_amount: u64) -> Result<Vec<Utxo>> {
        let unspent = self
            .mempool_electrs_client
            .get_address_utxos(&self.wallet.address.to_string())
            .await?;

        let mut suitable_utxos: Vec<Utxo> = unspent
            .iter()
            // TODO: Do we care if it's confirmed or not?
            .filter(|utxo| utxo.value >= required_amount)
            .cloned()
            .collect();

        // sort by value (with highest value first)
        suitable_utxos.sort_by_key(|utxo| Reverse(utxo.value));

        Ok(suitable_utxos)
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let config = MakerConfig::parse();

    // Create and run the market maker
    let mut market_maker = MarketMaker::new(config).await?;
    market_maker.run().await?;

    Ok(())
}
