mod mempool_electrs;

use crate::mempool_electrs::MempoolElectrsClient;
use alloy::primitives::Address;
use alloy::sol_types::SolValue;
use bitcoincore_rpc_async::RpcApi;
use clap::Parser;
use data_engine::engine::DataEngine;
use eyre::{eyre, Result};
use mempool_electrs::Utxo;
use rift_core::vaults::hash_deposit_vault;
use rift_sdk::bindings::Types::DepositVault;
use rift_sdk::{
    bitcoin_utils::AsyncBitcoinClient,
    create_websocket_provider,
    txn_builder::{build_rift_payment_transaction, P2WPKHBitcoinWallet},
    DatabaseLocation,
};
use std::{path::PathBuf, str::FromStr, sync::Arc, time::Duration};
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

    /// Market Maker's Bitcoin Private Key (WIF format)
    #[arg(long, env = "BTC_PRIVATE_KEY")]
    btc_private_key: String,

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
    #[arg(long, env = "FEE_SATS", default_value = "1000")]
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
    data_engine: DataEngine,
    config: MakerConfig,
    mempool_electrs_client: Arc<MempoolElectrsClient>,
}

fn get_qualified_payment_database_path(database_location: String) -> String {
    let path = PathBuf::from(database_location);
    let payment_db_path = path.join("payment.db");
    payment_db_path.to_str().expect("Invalid path").to_string()
}

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

        let provider = Arc::new(create_websocket_provider(&config.evm_ws_url).await?);
        let checkpoint_leaves =
            checkpoint_downloader::decompress_checkpoint_file(&config.checkpoint_file).unwrap();

        let data_engine = DataEngine::start(
            &config.db_location,
            provider,
            config.rift_contract_address,
            config.rift_deployment_block_number,
            checkpoint_leaves,
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

        // Initialize wallet from private key
        let network = bitcoin::Network::Bitcoin; // Use appropriate network
        let private_key = bitcoin::PrivateKey::from_str(&config.btc_private_key)?;
        let secret_key = private_key.inner;

        let wallet = P2WPKHBitcoinWallet::from_secret_bytes(&secret_key.secret_bytes(), network);

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
        })
    }

    /// Run the market maker loop
    async fn run(&self) -> Result<()> {
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
    async fn process_fillable_swaps(&self) -> Result<usize> {
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

        Ok(deposits)
    }

    /// Filter out deposits that we've already processed
    async fn filter_processed_deposits(
        &self,
        deposits: Vec<DepositVault>,
    ) -> Result<Vec<DepositVault>> {
        let mut unprocessed = Vec::new();

        for deposit in deposits {
            let commitment = format!(
                "0x{}",
                hex::encode(hash_deposit_vault(
                    &sol_types::Types::DepositVault::abi_decode(&deposit.abi_encode(), false)
                        .unwrap()
                ))
            );

            let already_processed = self
                .payment_database_connection
                .call(move |conn| {
                    let mut stmt = conn.prepare(
                        "SELECT COUNT(*) FROM processed_swaps WHERE deposit_commitment = ?1",
                    )?;

                    let count: i64 = stmt.query_row(params![commitment], |row| row.get(0))?;

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
    async fn process_deposit(&self, deposit: DepositVault) -> Result<()> {
        info!(
            "Processing deposit with expected sats: {}",
            deposit.expectedSats
        );

        // Find a suitable UTXO
        let utxos = self
            .find_suitable_utxos(deposit.expectedSats + self.config.fee_sats)
            .await?;

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
        )?;

        let canon_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &bitcoincore_rpc_async::bitcoin::consensus::serialize(&tx),
        )?;

        // Build the transaction paying to the deposit's scriptPubKey
        let payment_tx = build_rift_payment_transaction(
            &sol_types::Types::DepositVault::abi_decode(&deposit.abi_encode(), false).unwrap(),
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
        let commitment = format!(
            "0x{}",
            hex::encode(hash_deposit_vault(
                &sol_types::Types::DepositVault::abi_decode(&deposit.abi_encode(), false).unwrap(),
            ))
        );
        let tx_hex = tx_result.to_string();
        let now = chrono::Utc::now().timestamp();

        let cc_commitment = commitment.clone();
        self.payment_database_connection
            .call(move |conn| {
                conn.execute(
                "INSERT INTO processed_swaps (deposit_commitment, txid, amount_sats, timestamp) 
                 VALUES (?1, ?2, ?3, ?4)",
                params![commitment.clone(), tx_hex, deposit.expectedSats, now],
            )?;
                Ok::<_, tokio_rusqlite::Error>(())
            })
            .await?;

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

        let suitable_utxos = unspent
            .iter()
            // TODO: Do we care if it's confirmed or not?
            .filter(|utxo| utxo.value >= required_amount)
            .cloned()
            .collect();

        Ok(suitable_utxos)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let config = MakerConfig::parse();

    // Create and run the market maker
    let market_maker = MarketMaker::new(config).await?;
    market_maker.run().await?;

    Ok(())
}
