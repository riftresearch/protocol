//! `lib.rs` — central library code.

pub mod bitcoin_devnet;
pub mod evm_devnet;

pub use bitcoin_devnet::BitcoinDevnet;
use checkpoint_downloader::decompress_checkpoint_file;
pub use evm_devnet::EthDevnet;

use evm_devnet::ForkConfig;
use eyre::Result;
use log::info;
use rift_sdk::proof_generator::ProofGeneratorType;
use sol_bindings::RiftExchangeHarnessInstance;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::{NamedTempFile, TempDir};
use tokio::task::JoinSet;
use tokio::time::Instant;

use rift_indexer::engine::RiftIndexer;
use rift_indexer_server::RiftIndexerServer;

use rift_sdk::{DatabaseLocation, MultichainAccount};

use bitcoincore_rpc_async::RpcApi;

use rift_sdk::bitcoin_utils::BitcoinClientExt;

// ================== Contract ABIs ================== //

const TOKEN_ADDRESS: &str = "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf";
const TOKEN_SYMBOL: &str = "cbBTC";
const _TOKEN_NAME: &str = "Coinbase Wrapped BTC";
const _TOKEN_DECIMALS: u8 = 8;
const TAKER_FEE_BIPS: u16 = 10;
const RIFT_INDEXER_SERVER_PORT: u16 = 50100;

use alloy::{hex, sol};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    TokenizedBTC,
    "../../contracts/artifacts/TokenizedBTC.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SP1MockVerifier,
    "../../contracts/artifacts/SP1MockVerifier.json"
);

use alloy::providers::{DynProvider, Provider};

pub type RiftExchangeHarnessWebsocket = RiftExchangeHarnessInstance<DynProvider>;

pub type TokenizedBTCWebsocket = TokenizedBTC::TokenizedBTCInstance<DynProvider>;

// ================== Deploy Function ================== //


use crate::evm_devnet::Mode;

const LOG_CHUNK_SIZE: u64 = 10000;

#[derive(serde::Serialize, serde::Deserialize)]
struct ContractMetadata {
    rift_exchange_address: String,
    token_address: String,
    verifier_address: String,
    deployment_block_number: u64,
    periphery: Option<PeripheryMetadata>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PeripheryMetadata {
    rift_auction_adapter_address: String,
}

pub struct RiftDevnetCache {
    pub cache_dir: PathBuf,
    populated: bool,
}

const CACHE_DIR_NAME: &str = "rift-devnet";
const BITCOIN_DATADIR_NAME: &str = "bitcoin-datadir";
const ESPLORA_DATADIR_NAME: &str = "esplora-datadir";
const BITCOIN_DATA_ENGINE_DB_NAME: &str = "bitcoin-data-engine-db";
const ANVIL_DATADIR_NAME: &str = "anvil-datadir";
const RIFT_INDEXER_DB_NAME: &str = "data-engine-db";
const BITCOIN_CHECKPOINT_LEAVES_NAME: &str = "bitcoin-checkpoint-leaves.bin";
const ERROR_MESSAGE: &str = "Cache must be populated before utilizing it,";

pub fn get_new_temp_dir() -> Result<tempfile::TempDir> {
    Ok(tempfile::tempdir().unwrap())
}

pub fn get_new_temp_file() -> Result<NamedTempFile> {
    Ok(NamedTempFile::new()?)
}

impl Default for RiftDevnetCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RiftDevnetCache {
    pub fn new() -> Self {
        let cache_dir = dirs::cache_dir().unwrap().join(CACHE_DIR_NAME);
        let populated = cache_dir.exists();
        Self {
            cache_dir,
            populated,
        }
    }

    async fn copy_cached_file(
        &self,
        file_path: &str,
        operation_name: &str,
    ) -> Result<tempfile::NamedTempFile> {
        if !self.populated {
            return Err(eyre::eyre!("{} {}", ERROR_MESSAGE, operation_name));
        }

        let cache_file = self.cache_dir.join(file_path);
        let temp_file = get_new_temp_file()?;
        let temp_file_path = temp_file.path().to_path_buf();

        let output = tokio::process::Command::new("cp")
            .arg(&cache_file)
            .arg(&temp_file_path)
            .output()
            .await?;

        if !output.status.success() {
            return Err(eyre::eyre!(
                "Failed to copy {}: {}",
                operation_name,
                output.status
            ));
        }

        Ok(temp_file)
    }

    /// Generic helper to copy a cached directory to a new temporary directory
    async fn copy_cached_dir(
        &self,
        dir_name: &str,
        operation_name: &str,
    ) -> Result<tempfile::TempDir> {
        if !self.populated {
            return Err(eyre::eyre!("{} {}", ERROR_MESSAGE, operation_name));
        }

        let cache_dir = self.cache_dir.join(dir_name);
        let temp_dir = get_new_temp_dir()?;

        // We need to copy the directory contents, not the directory itself
        let output = tokio::process::Command::new("cp")
            .arg("-R")
            .arg(format!("{}/.", cache_dir.to_string_lossy()))
            .arg(temp_dir.path())
            .output()
            .await?;

        if !output.status.success() {
            return Err(eyre::eyre!(
                "Failed to copy {}: {}",
                operation_name,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(temp_dir)
    }

    pub async fn create_bitcoin_datadir(&self) -> Result<tempfile::TempDir> {
        let temp_dir = self
            .copy_cached_dir(BITCOIN_DATADIR_NAME, "bitcoin datadir")
            .await?;

        // Remove the cached .cookie file as bitcoind will generate a new one
        let cookie_path = temp_dir.path().join("regtest").join(".cookie");
        if cookie_path.exists() {
            tokio::fs::remove_file(&cookie_path).await?;
            tracing::info!("Removed cached .cookie file to allow bitcoind to generate a new one");
        }

        Ok(temp_dir)
    }

    pub async fn create_bitcoin_data_engine_db(&self) -> Result<tempfile::TempDir> {
        self.copy_cached_dir(BITCOIN_DATA_ENGINE_DB_NAME, "bitcoin data engine db")
            .await
    }

    pub async fn create_rift_indexer_db(&self) -> Result<tempfile::TempDir> {
        self.copy_cached_dir(RIFT_INDEXER_DB_NAME, "rift indexer db")
            .await
    }

    pub async fn create_electrsd_datadir(&self) -> Result<tempfile::TempDir> {
        self.copy_cached_dir(ESPLORA_DATADIR_NAME, "electrsd datadir")
            .await
    }

    pub async fn create_bitcoin_checkpoint_leaves(&self) -> Result<NamedTempFile> {
        self.copy_cached_file(BITCOIN_CHECKPOINT_LEAVES_NAME, "bitcoin checkpoint leaves")
            .await
    }

    pub async fn create_anvil_datadir(&self) -> Result<tempfile::TempDir> {
        self.copy_cached_dir(ANVIL_DATADIR_NAME, "anvil datadir")
            .await
    }

    pub async fn save_devnet(&self, mut devnet: RiftDevnet) -> Result<()> {
        use fs2::FileExt;
        use std::fs;
        let save_start = Instant::now();

        // Create cache directory if it doesn't exist
        fs::create_dir_all(&self.cache_dir)?;

        // Get a file lock to prevent concurrent saves
        let lock_file_path = self.cache_dir.join(".lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_file_path)?;

        // Try to get exclusive lock
        lock_file
            .try_lock_exclusive()
            .map_err(|_| eyre::eyre!("Another process is already saving the cache"))?;

        // Check if cache was populated while waiting for lock
        if self.cache_dir.join(BITCOIN_DATADIR_NAME).exists() {
            tracing::info!("Cache already populated by another process");
            return Ok(());
        }

        info!("[Cache] Starting devnet save to cache...");

        // stop all tasks in the join set so the services dont complain about bitcoin + evm shutting down
        devnet.join_set.abort_all();

        // 1. Gracefully shut down Bitcoin Core to ensure all blocks are flushed to disk
        let bitcoin_shutdown_start = Instant::now();
        info!("[Cache] Shutting down Bitcoin Core to flush all data to disk...");
        match devnet.bitcoin.rpc_client.stop().await {
            Ok(_) => {
                info!("[Cache] Bitcoin Core shutdown initiated successfully");
                // Wait a bit for shutdown to complete
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                info!(
                    "[Cache] Bitcoin shutdown took {:?}",
                    bitcoin_shutdown_start.elapsed()
                );
            }
            Err(e) => {
                // If stop fails, it might already be shutting down or have other issues
                tracing::warn!(
                    "Failed to stop Bitcoin Core gracefully: {}. Proceeding anyway.",
                    e
                );
            }
        }

        // 2. Gracefully shut down the anvil instance
        let anvil_shutdown_start = Instant::now();
        info!("[Cache] Shutting down Anvil to flush all data to disk...");
        let anvil_pid = devnet.ethereum.anvil.child().id();
        tokio::process::Command::new("kill")
            .arg("-SIGTERM")
            .arg(anvil_pid.to_string())
            .output()
            .await?;
        info!(
            "[Cache] Anvil shutdown took {:?}",
            anvil_shutdown_start.elapsed()
        );

        // 2. Save Bitcoin datadir (now with all blocks properly flushed)
        let copy_start = Instant::now();
        info!("[Cache] Starting to copy directories to cache...");
        let bitcoin_datadir_src = devnet.bitcoin.bitcoin_datadir.path();
        let bitcoin_datadir_dst = self.cache_dir.join(BITCOIN_DATADIR_NAME);
        let bitcoin_copy_start = Instant::now();
        Self::copy_dir_recursive(bitcoin_datadir_src, &bitcoin_datadir_dst).await?;
        info!(
            "[Cache] Bitcoin datadir copied in {:?}",
            bitcoin_copy_start.elapsed()
        );

        // Remove the .cookie file from cache as it will be regenerated on startup
        let cached_cookie = bitcoin_datadir_dst.join("regtest").join(".cookie");
        if cached_cookie.exists() {
            tokio::fs::remove_file(&cached_cookie).await?;
            info!("[Cache] Removed .cookie file from cache");
        }

        // 3. Save Bitcoin data engine DB
        let bitcoin_data_engine_db = &devnet.bitcoin.bitcoin_data_engine_datadir;
        let bitcoin_data_engine_dst = self.cache_dir.join(BITCOIN_DATA_ENGINE_DB_NAME);
        let bde_copy_start = Instant::now();
        Self::copy_dir_recursive(bitcoin_data_engine_db.path(), &bitcoin_data_engine_dst).await?;
        info!(
            "[Cache] Bitcoin data engine DB copied in {:?}",
            bde_copy_start.elapsed()
        );

        // 4. Save Electrsd datadir
        let electrsd_datadir_src = devnet.bitcoin.electrsd_datadir.path();
        let electrsd_datadir_dst = self.cache_dir.join(ESPLORA_DATADIR_NAME);
        let electrsd_copy_start = Instant::now();
        Self::copy_dir_recursive(electrsd_datadir_src, &electrsd_datadir_dst).await?;
        info!(
            "[Cache] Electrsd datadir copied in {:?}",
            electrsd_copy_start.elapsed()
        );

        // 5. Save Rift indexer DB
        let rift_indexer_datadir_src = devnet.rift_indexer_datadir.path();
        let rift_indexer_datadir_dst = self.cache_dir.join(RIFT_INDEXER_DB_NAME);
        let rift_indexer_copy_start = Instant::now();
        Self::copy_dir_recursive(rift_indexer_datadir_src, &rift_indexer_datadir_dst).await?;
        info!(
            "[Cache] Rift indexer DB copied in {:?}",
            rift_indexer_copy_start.elapsed()
        );

        // 6. Save Bitcoin checkpoint leaves
        let checkpoint_src = devnet.checkpoint_file_handle.path();
        let checkpoint_dst = self.cache_dir.join(BITCOIN_CHECKPOINT_LEAVES_NAME);
        let checkpoint_copy_start = Instant::now();
        tokio::fs::copy(checkpoint_src, &checkpoint_dst).await?;
        info!(
            "[Cache] Checkpoint leaves copied in {:?}",
            checkpoint_copy_start.elapsed()
        );

        // 7. Save Anvil state file
        // Anvil automatically dumps state on exit to the anvil_datafile when --dump-state is used
        // We just need to copy it to our cache directory
        let anvil_dump_path = devnet.ethereum.anvil_dump_path.path();
        info!(
            "[Cache] Saving anvil state from {}",
            anvil_dump_path.to_string_lossy()
        );

        let anvil_dst = self.cache_dir.join(ANVIL_DATADIR_NAME);
        let anvil_copy_start = Instant::now();
        Self::copy_dir_recursive(anvil_dump_path, &anvil_dst).await?;
        info!(
            "[Cache] Anvil state copied in {:?}",
            anvil_copy_start.elapsed()
        );

        // Also save contract metadata
        let metadata = ContractMetadata {
            rift_exchange_address: devnet.ethereum.rift_exchange_contract.address().to_string(),
            token_address: devnet.ethereum.token_contract.address().to_string(),
            verifier_address: devnet.ethereum.verifier_contract.to_string(),
            deployment_block_number: devnet.ethereum.deployment_block_number,
            periphery: devnet
                .ethereum
                .periphery
                .as_ref()
                .map(|p| PeripheryMetadata {
                    rift_auction_adapter_address: p.rift_auction_adapter.address().to_string(),
                }),
        };

        let metadata_path = self.cache_dir.join("contracts.json");
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        let metadata_start = Instant::now();
        tokio::fs::write(&metadata_path, metadata_json).await?;
        info!(
            "[Cache] Contract metadata saved in {:?}",
            metadata_start.elapsed()
        );

        info!(
            "[Cache] Total directory copying took {:?}",
            copy_start.elapsed()
        );

        // Release lock by dropping it
        drop(lock_file);

        info!(
            "[Cache] Devnet saved to cache successfully! Total time: {:?}",
            save_start.elapsed()
        );
        Ok(())
    }

    async fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
        tokio::fs::create_dir_all(dst).await?;

        // Copy contents of src to dst
        let output = tokio::process::Command::new("cp")
            .arg("-R")
            .arg(format!("{}/.", src.to_string_lossy()))
            .arg(dst)
            .output()
            .await?;

        if !output.status.success() {
            return Err(eyre::eyre!(
                "Failed to copy directory: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }
}

// ================== RiftDevnet ================== //

/// The "combined" Devnet which holds:
/// - a `BitcoinDevnet`
/// - an `EthDevnet`
/// - an optional `RiftIndexer` and `RiftIndexerServer`
pub struct RiftDevnet {
    pub bitcoin: BitcoinDevnet,
    pub ethereum: EthDevnet,
    pub rift_indexer: Arc<RiftIndexer>,
    pub join_set: JoinSet<eyre::Result<()>>,
    pub checkpoint_file_handle: NamedTempFile,
    pub rift_indexer_datadir: tempfile::TempDir,
    #[allow(dead_code)]
    hypernode_db_dir: Option<TempDir>,
    #[allow(dead_code)]
    market_maker_db_dir: Option<TempDir>,
    _rift_indexer_server: Option<RiftIndexerServer>,
}

impl RiftDevnet {
    pub fn builder() -> RiftDevnetBuilder {
        RiftDevnetBuilder::new()
    }

    pub fn builder_for_cached() -> RiftDevnetBuilder {
        RiftDevnetBuilder::for_cached()
    }
}

/// A builder for configuring a `RiftDevnet` instantiation.
#[derive(Default)]
pub struct RiftDevnetBuilder {
    interactive: bool,
    funded_evm_addresses: Vec<String>,
    funded_bitcoin_addreses: Vec<String>,
    fork_config: Option<ForkConfig>,
    using_esplora: bool,
}

impl RiftDevnetBuilder {
    /// Create a new builder with all default values.
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a builder with settings for a cached devnet.
    pub fn for_cached() -> Self {
        RiftDevnetBuilder {
            interactive: false,
            funded_evm_addresses: vec![],
            funded_bitcoin_addreses: vec![],
            fork_config: None,
            using_esplora: true,
        }
    }

    /// Toggle whether the devnet runs in "interactive" mode:
    /// - If true, binds Anvil on a stable port and starts a local RiftIndexerServer.
    /// - If false, does minimal ephemeral setup.
    pub fn interactive(mut self, value: bool) -> Self {
        self.interactive = value;
        self
    }

    /// Optionally fund a given EVM address with Ether and tokens.
    pub fn funded_evm_address<T: Into<String>>(mut self, address: T) -> Self {
        self.funded_evm_addresses.push(address.into());
        self
    }

    /// Optionally fund a given Bitcoin address.
    pub fn funded_bitcoin_address<T: Into<String>>(mut self, address: T) -> Self {
        self.funded_bitcoin_addreses.push(address.into());
        self
    }

    /// Provide a fork configuration (RPC URL/block) if you want to fork a public chain.
    pub fn fork_config(mut self, config: ForkConfig) -> Self {
        self.fork_config = Some(config);
        self
    }

    /// Start a blockstream/electrs esplora REST API server for bitcoin data indexing.
    pub fn using_esplora(mut self, value: bool) -> Self {
        self.using_esplora = value;
        self
    }

    pub async fn build(self) -> Result<(crate::RiftDevnet, u64)> {
        // dont bother with the cache if we're in interactive mode for now
        // could help startup time a little bit if we care to enable it later
        if self.interactive {
            Ok(self.build_internal(None).await?)
        } else {
            let cache = Arc::new(RiftDevnetCache::new());

            if cache.populated {
                tracing::info!("Cache directory exists, loading devnet from cache...");
                let (devnet, funded_sats) = self.build_internal(Some(cache.clone())).await?;
                Ok((devnet, funded_sats))
            } else {
                tracing::info!("Cache directory does not exist, building fresh devnet...");
                let (devnet, funded_sats) = self.build_internal(None).await?;
                Ok((devnet, funded_sats))
            }
        }
    }

    /// Actually build the `RiftDevnet`, consuming this builder.
    ///
    /// Returns a tuple of:
    ///   - The devnet instance
    ///   - The number of satoshis funded to `funded_bitcoin_address` (if any)
    async fn build_internal(
        self,
        devnet_cache: Option<Arc<RiftDevnetCache>>,
    ) -> Result<(crate::RiftDevnet, u64)> {
        let build_start = Instant::now();
        info!("[Devnet Builder] Starting devnet build...");
        let mut join_set = JoinSet::new();

        // 1) Bitcoin side
        let bitcoin_start = Instant::now();
        let (bitcoin_devnet, current_mined_height) = crate::bitcoin_devnet::BitcoinDevnet::setup(
            self.funded_bitcoin_addreses.clone(),
            self.using_esplora,
            self.interactive,
            &mut join_set,
            devnet_cache.clone(),
        )
        .await
        .map_err(|e| eyre::eyre!("[devnet builder] Failed to setup Bitcoin devnet: {}", e))?;
        info!(
            "[Devnet Builder] Bitcoin devnet setup took {:?}",
            bitcoin_start.elapsed()
        );

        // Drop build lock here, only really necessary for bitcoin devnet setup
        let funding_sats = bitcoin_devnet.funded_sats;

        // 2) Collect Bitcoin checkpoint leaves
        let checkpoint_start = Instant::now();
        info!(
            "[Devnet Builder] Processing checkpoint leaves from block range 0..{}",
            current_mined_height
        );
        let (mut rift_indexer, tip_block_leaf, checkpoint_file_handle, rift_indexer_datadir) =
            match devnet_cache.clone() {
                Some(devnet_cache) if devnet_cache.populated => {
                    info!("[Devnet Builder] Loading checkpoint leaves from cache...");
                    let tip_block_leaf = bitcoin_devnet
                        .rpc_client
                        .get_leaves_from_block_range(
                            current_mined_height,
                            current_mined_height,
                            2,
                            None,
                        )
                        .await
                        .map_err(|e| {
                            eyre::eyre!("[devnet builder] Failed to get tip block leaf: {}", e)
                        })?;
                    let tip_block_leaf = *tip_block_leaf.last().unwrap();
                    let checkpoint_file_handle =
                        devnet_cache.create_bitcoin_checkpoint_leaves().await?;
                    let checkpoint_file_path =
                        checkpoint_file_handle.path().to_string_lossy().to_string();
                    let checkpoint_leaves = decompress_checkpoint_file(&checkpoint_file_path)?;

                    let rift_indexer_datadir = devnet_cache.create_rift_indexer_db().await?;

                    let rift_indexer = rift_indexer::engine::RiftIndexer::seed(
                        &DatabaseLocation::Directory(
                            rift_indexer_datadir.path().to_string_lossy().to_string(),
                        ),
                        checkpoint_leaves,
                    )
                    .await
                    .map_err(|e| {
                        eyre::eyre!("[devnet builder] Failed to seed data engine: {}", e)
                    })?;
                    info!(
                        "[Devnet Builder] Loaded checkpoint data from cache in {:?}",
                        checkpoint_start.elapsed()
                    );
                    (
                        rift_indexer,
                        tip_block_leaf,
                        checkpoint_file_handle,
                        rift_indexer_datadir,
                    )
                }
                _ => {
                    info!("[Devnet Builder] Downloading fresh checkpoint leaves...");
                    let download_start = Instant::now();
                    let checkpoint_leaves = bitcoin_devnet
                        .rpc_client
                        .get_leaves_from_block_range(0, current_mined_height, 100, None)
                        .await
                        .map_err(|e| {
                            eyre::eyre!("[devnet builder] Failed to get checkpoint leaves: {}", e)
                        })?;
                    info!(
                        "[Devnet Builder] Downloaded {} checkpoint leaves in {:?}",
                        checkpoint_leaves.len(),
                        download_start.elapsed()
                    );

                    // 3) Save compressed leaves to a named temp file
                    let compress_start = Instant::now();
                    let checkpoint_file_handle = get_new_temp_file()?;
                    let output_file_path =
                        checkpoint_file_handle.path().to_string_lossy().to_string();
                    checkpoint_downloader::compress_checkpoint_leaves(
                        &checkpoint_leaves,
                        output_file_path.as_str(),
                    )
                    .map_err(|e| {
                        eyre::eyre!(
                            "[devnet builder] Failed to compress checkpoint leaves: {}",
                            e
                        )
                    })?;
                    info!(
                        "[Devnet Builder] Compressed checkpoint leaves in {:?}",
                        compress_start.elapsed()
                    );
                    let tip_block_leaf = *checkpoint_leaves.last().unwrap();
                    let rift_indexer_datadir = get_new_temp_dir()?;
                    println!("tip_block_leaf: {:?}", tip_block_leaf);
                    println!(
                        "last checkpoint_leaf: {:?}",
                        checkpoint_leaves.last().unwrap()
                    );

                    // 4) Create/seed DataEngine
                    info!("[Devnet Builder] Seeding data engine with checkpoint leaves...");
                    let seed_start = Instant::now();
                    let rift_indexer = rift_indexer::engine::RiftIndexer::seed(
                        &DatabaseLocation::Directory(
                            rift_indexer_datadir.path().to_string_lossy().to_string(),
                        ),
                        checkpoint_leaves,
                    )
                    .await
                    .map_err(|e| {
                        eyre::eyre!("[devnet builder] Failed to seed data engine: {}", e)
                    })?;
                    info!(
                        "[Devnet Builder] Data engine seeded in {:?}",
                        seed_start.elapsed()
                    );
                    info!(
                        "[Devnet Builder] Total checkpoint processing took {:?}",
                        checkpoint_start.elapsed()
                    );
                    (
                        rift_indexer,
                        tip_block_leaf,
                        checkpoint_file_handle,
                        rift_indexer_datadir,
                    )
                }
            };

        let deploy_mode = if self.interactive {
            Mode::Fork(self.fork_config.clone().unwrap())
        } else {
            Mode::Local
        };

        // 5) Ethereum side
        let ethereum_start = Instant::now();

        let circuit_verification_key_hash =
            hex!("0xdeadbeeeeeef0000000000000000000000000000000000000000000000000000"); // rift_sdk::get_rift_program_hash(); // TODO: once we support a real proof mode, this will be important

        let (ethereum_devnet, deployment_block_number) = crate::evm_devnet::EthDevnet::setup(
            circuit_verification_key_hash,
            rift_indexer
                .get_mmr_root()
                .await
                .map_err(|e| eyre::eyre!("[devnet builder] Failed to get MMR root: {}", e))?,
            tip_block_leaf,
            deploy_mode,
            devnet_cache.clone(),
        )
        .await
        .map_err(|e| eyre::eyre!("[devnet builder] Failed to setup Ethereum devnet: {}", e))?;

        info!(
            "[Devnet Builder] Ethereum devnet setup took {:?}",
            ethereum_start.elapsed()
        );

        // 6) Start listening to on-chain events

        let rift_indexer_start = tokio::time::Instant::now();
        rift_indexer
            .start_event_listener(
                ethereum_devnet.funded_provider.clone(),
                *ethereum_devnet.rift_exchange_contract.address(),
                deployment_block_number,
                LOG_CHUNK_SIZE,
                &mut join_set,
            )
            .await
            .map_err(|e| eyre::eyre!("[devnet builder] Failed to start event listener: {}", e))?;

        // 7) Wait for initial sync
        let rift_indexer = std::sync::Arc::new(rift_indexer);
        info!("Waiting for contract data engine initial sync...");
        rift_indexer
            .wait_for_initial_sync()
            .await
            .map_err(|e| eyre::eyre!("[devnet builder] Failed to wait for initial sync: {}", e))?;
        info!(
            "[Devnet Builder] Rift Indexer initial sync took {:?}",
            rift_indexer_start.elapsed()
        );

        // 8) Possibly run data-engine server in interactive mode
        let rift_indexer_server = if self.interactive {
            Some(
                rift_indexer_server::RiftIndexerServer::from_engine(
                    rift_indexer.clone(),
                    crate::RIFT_INDEXER_SERVER_PORT,
                    &mut join_set,
                )
                .await
                .map_err(|e| {
                    eyre::eyre!("[devnet builder] Failed to start data engine server: {}", e)
                })?,
            )
        } else {
            None
        };

        // 9) Fund optional EVM address with Ether + tokens
        let funding_start = if !self.funded_evm_addresses.is_empty() {
            info!(
                "[Devnet Builder] Funding {} EVM addresses...",
                self.funded_evm_addresses.len()
            );
            Some(Instant::now())
        } else {
            None
        };
        for addr_str in self.funded_evm_addresses.clone() {
            use alloy::primitives::Address;
            use std::str::FromStr;
            let address = Address::from_str(&addr_str)?; // TODO: check if this is correct

            // ~10 ETH
            ethereum_devnet
                .fund_eth_address(
                    address,
                    alloy::primitives::U256::from_str("10000000000000000000")?,
                )
                .await
                .map_err(|e| eyre::eyre!("[devnet builder] Failed to fund ETH address: {}", e))?;

            // ~10 tokens with 18 decimals
            ethereum_devnet
                .mint_token(
                    address,
                    alloy::primitives::U256::from_str("10000000000000000000")?,
                )
                .await
                .map_err(|e| eyre::eyre!("[devnet builder] Failed to mint token: {}", e))?;

            // Debugging: check funded balances
            let eth_balance = ethereum_devnet
                .funded_provider
                .get_balance(address)
                .await
                .map_err(|e| eyre::eyre!("[devnet builder] Failed to get ETH balance: {}", e))?;
            info!(
                "[Devnet Builder] Ether Balance of {} => {:?}",
                addr_str, eth_balance
            );
            let token_balance = ethereum_devnet
                .token_contract
                .balanceOf(address)
                .call()
                .await
                .map_err(|e| eyre::eyre!("[devnet builder] Failed to get token balance: {}", e))?;
            info!(
                "[Devnet Builder] Token Balance of {} => {:?}",
                addr_str, token_balance
            );
        }
        if let Some(start) = funding_start {
            info!("[Devnet Builder] Funded addresses in {:?}", start.elapsed());
        }

        // 10) Setup interactive mode if enabled
        let (hypernode_db_dir, market_maker_db_dir) = if self.interactive {
            let (hypernode_db_dir, market_maker_db_dir) = self
                .setup_interactive_mode(
                    &bitcoin_devnet,
                    &ethereum_devnet,
                    checkpoint_file_handle.path().to_string_lossy().as_ref(),
                    deployment_block_number,
                    self.using_esplora,
                    &mut join_set,
                )
                .await?;

            (Some(hypernode_db_dir), Some(market_maker_db_dir))
        } else {
            (None, None)
        };

        // 11) Return the final devnet
        let devnet = crate::RiftDevnet {
            bitcoin: bitcoin_devnet,
            ethereum: ethereum_devnet,
            rift_indexer,
            rift_indexer_datadir,
            join_set,
            _rift_indexer_server: rift_indexer_server,
            checkpoint_file_handle,
            hypernode_db_dir,
            market_maker_db_dir,
        };
        info!(
            "[Devnet Builder] Devnet setup took {:?}",
            build_start.elapsed()
        );

        Ok((devnet, funding_sats))
    }

    /// Setup interactive mode with hypernode, market maker, auto-mining, and logging
    async fn setup_interactive_mode(
        &self,
        bitcoin_devnet: &BitcoinDevnet,
        ethereum_devnet: &EthDevnet,
        checkpoint_file_path: &str,
        deployment_block_number: u64,
        using_esplora: bool,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<(TempDir, TempDir)> {
        let setup_start = Instant::now();
        let hypernode_account = MultichainAccount::new(151);
        let market_maker_account = MultichainAccount::new(152);

        // Fund accounts with ETH
        let funding_start = Instant::now();
        info!("[Interactive Setup] Funding accounts with ETH...");
        ethereum_devnet
            .fund_eth_address(
                hypernode_account.ethereum_address,
                alloy::primitives::U256::from_str_radix("1000000000000000000000000", 10)?,
            )
            .await
            .map_err(|e| {
                eyre::eyre!(
                    "[devnet builder-hypernode] Failed to fund ETH address: {}",
                    e
                )
            })?;

        ethereum_devnet
            .fund_eth_address(
                market_maker_account.ethereum_address,
                alloy::primitives::U256::from_str_radix("1000000000000000000000000", 10)?,
            )
            .await
            .map_err(|e| {
                eyre::eyre!(
                    "[devnet builder-market_maker] Failed to fund ETH address: {}",
                    e
                )
            })?;

        // Fund market maker with Bitcoin
        info!("[Interactive Setup] Funding market maker with Bitcoin...");
        bitcoin_devnet
            .deal_bitcoin(
                market_maker_account.bitcoin_wallet.address.clone(),
                bitcoin::Amount::from_btc(100.0).unwrap(),
            )
            .await
            .map_err(|e| {
                eyre::eyre!(
                    "[devnet builder-market_maker] Failed to deal bitcoin: {}",
                    e
                )
            })?;
        info!(
            "[Interactive Setup] Account funding took {:?}",
            funding_start.elapsed()
        );

        // Start hypernode
        let hypernode_db_dir = get_new_temp_dir()?;
        let hypernode_db_location = DatabaseLocation::InMemory;
        // DatabaseLocation::Directory(hypernode_db_dir.path().to_string_lossy().to_string());
        let hypernode_start = Instant::now();
        info!("[Interactive Setup] Starting hypernode...");
        let hypernode_args = hypernode::HypernodeArgs {
            evm_ws_rpc: ethereum_devnet.anvil.ws_endpoint_url().to_string(),
            btc_rpc: bitcoin_devnet.rpc_url_with_cookie.clone(),
            private_key: hex::encode(hypernode_account.secret_bytes),
            checkpoint_file: checkpoint_file_path.to_string(),
            database_location: hypernode_db_location,
            rift_exchange_address: ethereum_devnet.rift_exchange_contract.address().to_string(),
            deploy_block_number: deployment_block_number,
            evm_log_chunk_size: LOG_CHUNK_SIZE,
            btc_batch_rpc_size: 100,
            proof_generator: ProofGeneratorType::Execute,
            enable_auto_light_client_update: false,
            auto_light_client_update_block_lag_threshold: 6,
            auto_light_client_update_check_interval_secs: 30,
        };

        join_set.spawn(async move {
            hypernode_args
                .run()
                .await
                .map_err(|e| eyre::eyre!("Hypernode failed: {}", e))
        });
        info!(
            "[Interactive Setup] Hypernode started in {:?}",
            hypernode_start.elapsed()
        );

        // Start market maker
        let market_maker_start = Instant::now();
        info!("[Interactive Setup] Starting market maker...");
        let market_maker_db_dir = get_new_temp_dir()?;
        let market_maker_db_location = DatabaseLocation::InMemory;
        // DatabaseLocation::Directory(market_maker_db_dir.path().to_string_lossy().to_string());
        let maker_config = market_maker::MakerConfig {
            evm_ws_rpc: ethereum_devnet.anvil.ws_endpoint_url().to_string(),
            btc_rpc: bitcoin_devnet.rpc_url_with_cookie.clone(),
            btc_rpc_timeout_ms: 10000,
            evm_private_key: hex::encode(hypernode_account.secret_bytes),
            btc_mnemonic: market_maker_account.bitcoin_mnemonic.to_string(),
            btc_mnemonic_passphrase: None,
            btc_mnemonic_derivation_path: None,
            btc_network: bitcoin::Network::Regtest,
            auction_house_address: ethereum_devnet.rift_exchange_contract.address().to_string(),
            spread_bps: 1, // TODO: make this zero once the market maker doesnt break
            max_batch_size: 5,
            btc_tx_size_vbytes: None,
            esplora_api_url: bitcoin_devnet
                .esplora_url
                .clone()
                .expect("Esplora URL is required for market maker"),
            checkpoint_file: checkpoint_file_path.to_string(),
            database_location: market_maker_db_location,
            deploy_block_number: deployment_block_number,
            evm_log_chunk_size: LOG_CHUNK_SIZE,
            btc_batch_rpc_size: 100,
            chain_id: ethereum_devnet.anvil.chain_id(),
            order_delay_seconds: 5,
            order_max_batch_size: 5,
            order_required_confirmations: 2,
            order_confirmation_timeout: 300,
            coinbase_api_key: None,
            coinbase_api_secret: None,
            market_maker_btc_address: None,
            cbbtc_contract_address: None,
            minimum_redeem_threshold_sats: 1000000,
        };

        join_set.spawn(async move {
            maker_config
                .run()
                .await
                .map_err(|e| eyre::eyre!("Market Maker failed: {}", e))
        });
        info!(
            "[Interactive Setup] Market maker started in {:?}",
            market_maker_start.elapsed()
        );

        // Start auto-mining task
        info!("[Interactive Setup] Starting Bitcoin auto-mining task...");
        let bitcoin_rpc_url = bitcoin_devnet.rpc_url_with_cookie.clone();
        let miner_address = bitcoin_devnet.miner_address.clone();
        let cookie = bitcoin_devnet.cookie.clone();

        join_set.spawn(async move {
            use bitcoincore_rpc_async::{Auth, Client as AsyncBitcoinRpcClient, RpcApi};

            // Create dedicated RPC client for mining
            // Use Auth::None since credentials are already embedded in the URL
            let mining_client =
                match AsyncBitcoinRpcClient::new(bitcoin_rpc_url, Auth::CookieFile(cookie)).await {
                    Ok(client) => client,
                    Err(e) => {
                        log::error!("Failed to create mining RPC client: {}", e);
                        return Ok(());
                    }
                };

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                match mining_client.generate_to_address(1, &miner_address).await {
                    Ok(_) => {
                        log::debug!("Auto-mined Bitcoin block");
                    }
                    Err(e) => {
                        log::warn!("Failed to auto-mine Bitcoin block: {}", e);
                    }
                }
            }
        });
        info!("[Interactive Setup] Bitcoin auto-mining task started");

        // Log interactive info
        let periphery = ethereum_devnet.periphery.as_ref().unwrap();
        info!(
            "[Interactive Setup] Interactive mode setup complete in {:?}",
            setup_start.elapsed()
        );
        println!("---RIFT DEVNET---");
        println!(
            "Anvil HTTP Url:             http://0.0.0.0:{}",
            ethereum_devnet.anvil.port()
        );
        println!(
            "Anvil WS Url:               ws://0.0.0.0:{}",
            ethereum_devnet.anvil.port()
        );
        println!(
            "Forked Chain ID:             {}",
            ethereum_devnet.anvil.chain_id()
        );
        println!(
            "Data Engine HTTP URL:       http://0.0.0.0:{}",
            crate::RIFT_INDEXER_SERVER_PORT
        );
        println!(
            "Bitcoin RPC URL:            {}",
            bitcoin_devnet.rpc_url_with_cookie
        );

        if using_esplora {
            println!(
                "Esplora API URL:            {}",
                bitcoin_devnet.esplora_url.as_ref().unwrap()
            );
        }

        println!(
            "{} Address:              {}",
            crate::TOKEN_SYMBOL,
            ethereum_devnet.token_contract.address()
        );
        println!(
            "Rift Exchange Address:      {}",
            ethereum_devnet.rift_exchange_contract.address()
        );

        println!(
            "RiftAuctionAdapter Address: {}",
            periphery.rift_auction_adapter.address()
        );

        println!(
            "MM Bitcoin Address:         {}",
            market_maker_account.bitcoin_wallet.address
        );

        println!("Hypernode:                  Running");
        println!("Market Maker:               Running");
        println!("Bitcoin Auto-mining:        Every 5 seconds");
        println!("Anvil Auto-mining:          Every 1 second");
        println!("---RIFT DEVNET---");

        Ok((hypernode_db_dir, market_maker_db_dir))
    }
}
