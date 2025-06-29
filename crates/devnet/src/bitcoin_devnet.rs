use std::sync::Arc;
use std::{path::PathBuf, str::FromStr, time::Duration};

use bitcoin_data_engine::BitcoinDataEngine;
use bitcoincore_rpc_async::bitcoin::Txid;
use bitcoincore_rpc_async::json::GetRawTransactionVerbose;
use corepc_node::Conf;
use eyre::{eyre, Result};
use log::info;
use rift_sdk::DatabaseLocation;
use tokio::task::JoinSet;
use tokio::time::Instant;

use bitcoin::{Address as BitcoinAddress, Amount};
use bitcoincore_rpc_async::Auth;
use bitcoincore_rpc_async::RpcApi;
use corepc_node::Node as BitcoinRegtest;
use electrsd::ElectrsD;
use esplora_client::AsyncClient as EsploraClient;

use crate::{get_new_temp_dir, RiftDevnetCache};
use rift_sdk::bitcoin_utils::AsyncBitcoinClient;

/// Holds all Bitcoin-related devnet state.
pub struct BitcoinDevnet {
    pub data_engine: Arc<BitcoinDataEngine>,
    pub rpc_client: Arc<AsyncBitcoinClient>,
    pub miner_address: BitcoinAddress,
    pub cookie: PathBuf,
    pub datadir: PathBuf,
    pub rpc_url_with_cookie: String,
    pub electrsd: Option<Arc<ElectrsD>>,
    pub esplora_client: Option<Arc<EsploraClient>>,
    pub esplora_url: Option<String>,
    /// If you optionally funded a BTC address upon startup,
    /// we keep track of the satoshis here.
    pub funded_sats: u64,
    /// The bitcoin regtest node instance.
    /// This must be kept alive for the lifetime of the devnet.
    pub regtest: Arc<BitcoinRegtest>,
    pub bitcoin_datadir: tempfile::TempDir,
    pub bitcoin_data_engine_datadir: tempfile::TempDir,
    pub electrsd_datadir: tempfile::TempDir,
}

impl BitcoinDevnet {
    /// Create and initialize a new Bitcoin regtest environment
    /// with an optional `funded_address`.
    /// Returns `(BitcoinDevnet, AsyncBitcoinClient)` so we can
    /// also have an async RPC client if needed.
    pub async fn setup(
        funded_addresses: Vec<String>,
        using_esplora: bool,
        fixed_esplora_url: bool,
        join_set: &mut JoinSet<eyre::Result<()>>,
        devnet_cache: Option<Arc<RiftDevnetCache>>,
    ) -> Result<(Self, u32)> {
        info!("Instantiating Bitcoin Regtest...");
        let wallet_name = "alice";
        let t = Instant::now();
        let mut conf = Conf::default();
        conf.args.push("-txindex");
        conf.wallet = None;
        conf.view_stdout = false;

        let bitcoin_datadir = if let Some(devnet_cache) = devnet_cache.clone() {
            info!("[Bitcoin Setup] Using cached bitcoin datadir");
            devnet_cache.create_bitcoin_datadir().await?
        } else {
            info!("[Bitcoin Setup] Creating fresh bitcoin datadir");
            get_new_temp_dir()?
        };
        info!("[Bitcoin Setup] bitcoin_datadir: {:?}", bitcoin_datadir);

        conf.staticdir = Some(bitcoin_datadir.path().to_path_buf());
        conf.tmpdir = None;

        let bitcoin_regtest = Arc::new(
            tokio::task::spawn_blocking(move || BitcoinRegtest::from_downloaded_with_conf(&conf))
                .await
                .map_err(|e| eyre!("Failed to spawn blocking task: {}", e))?
                .map_err(|e| eyre!(e))?,
        );
        info!("Instantiated Bitcoin Regtest in {:?}", t.elapsed());

        // When loading from cache, give bitcoind more time to fully initialize
        if devnet_cache.is_some() {
            info!("Waiting for bitcoind to fully initialize from cached data...");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let datadir = bitcoin_regtest.workdir().join("regtest");

        let cookie = bitcoin_regtest.params.cookie_file.clone();

        // Wait for cookie file to be created and readable
        let mut cookie_str = String::new();
        for i in 0..20 {
            match tokio::fs::read_to_string(cookie.clone()).await {
                Ok(content) => {
                    cookie_str = content.trim().to_string(); // Trim any whitespace/newlines
                    info!("Successfully read cookie file after {} attempts", i + 1);
                    break;
                }
                Err(e) => {
                    if i == 19 {
                        return Err(eyre!("Failed to read cookie file after 20 attempts: {}", e));
                    }
                    info!("Cookie file not ready yet (attempt {}), waiting...", i + 1);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        // http://<user>:<password>@<host>:<port>/
        // Initially connect without wallet specification
        let rpc_url_with_cookie = format!(
            "http://{}@{}:{}",
            cookie_str,
            bitcoin_regtest.params.rpc_socket.ip(),
            bitcoin_regtest.params.rpc_socket.port()
        );
        let rpc_url = format!(
            "http://{}:{}",
            bitcoin_regtest.params.rpc_socket.ip(),
            bitcoin_regtest.params.rpc_socket.port()
        );

        info!("Creating async Bitcoin RPC client at {}", rpc_url);

        let bitcoin_rpc_client: Arc<AsyncBitcoinClient> = Arc::new(
            AsyncBitcoinClient::new(
                rpc_url_with_cookie.clone(),
                Auth::None,
                Duration::from_millis(10000),
            )
            .await?,
        );

        // Always ensure the wallet exists and recreate client with wallet URL
        // First check if we can connect to bitcoind
        match bitcoin_rpc_client.get_blockchain_info().await {
            Ok(stats) => info!("Successfully connected to bitcoind -> {:?}", stats),
            Err(e) => {
                return Err(eyre!("Failed to connect to bitcoind: {}", e));
            }
        }

        // Try to load the wallet, create it if it doesn't exist
        match bitcoin_rpc_client.load_wallet(wallet_name).await {
            Ok(_) => info!("Loaded existing wallet '{}'", wallet_name),
            Err(e) => {
                // Check if wallet already loaded (error code -35)
                if e.to_string().contains("already loaded") {
                    info!("Wallet '{}' already loaded", wallet_name);
                } else {
                    // Wallet doesn't exist or failed to load, create it
                    info!(
                        "Wallet '{}' not found or failed to load ({}), creating new wallet...",
                        wallet_name, e
                    );
                    match bitcoin_rpc_client
                        .create_wallet(wallet_name, None, None, None, None)
                        .await
                    {
                        Ok(_) => info!("Created new wallet '{}'", wallet_name),
                        Err(create_err) => {
                            return Err(eyre!(
                                "Failed to create wallet '{}': {}",
                                wallet_name,
                                create_err
                            ));
                        }
                    }
                }
            }
        }

        // Now recreate the client with the wallet in the URL
        let wallet_rpc_url = format!(
            "http://{}@{}:{}/wallet/{}",
            cookie_str,
            bitcoin_regtest.params.rpc_socket.ip(),
            bitcoin_regtest.params.rpc_socket.port(),
            wallet_name
        );
        let bitcoin_rpc_client = Arc::new(
            AsyncBitcoinClient::new(wallet_rpc_url, Auth::None, Duration::from_millis(10000))
                .await?,
        );

        let alice_address = bitcoin_rpc_client
            .get_new_address(None, None)
            .await?
            .assume_checked();

        if let Some(_devnet_cache) = &devnet_cache {
            info!("Using cached bitcoin blocks");
        } else {
            let mine_time = Instant::now();
            info!("Mining 101 blocks to miner...");
            bitcoin_rpc_client
                .generate_to_address(101, &alice_address)
                .await?;

            info!("Mined 101 blocks in {:?}", mine_time.elapsed());
        }
        let bitcoin_data_engine_datadir = if let Some(devnet_cache) = &devnet_cache {
            devnet_cache.create_bitcoin_data_engine_db().await?
        } else {
            get_new_temp_dir()?
        };

        let bde_db_location = DatabaseLocation::Directory(
            bitcoin_data_engine_datadir
                .path()
                .to_string_lossy()
                .to_string(),
        );

        let (data_engine, (electrsd, esplora_client, esplora_url, electrsd_datadir)) = tokio::try_join!(
            Self::setup_data_engine(bde_db_location, bitcoin_rpc_client.clone(), join_set),
            Self::setup_electrsd_and_esplora(
                using_esplora,
                fixed_esplora_url,
                devnet_cache,
                bitcoin_regtest.clone(),
            )
        )?;

        // If user wants to fund a specific BTC address
        let mut funded_sats = 0;
        let mut txids = Vec::new();
        for addr_str in funded_addresses {
            let amount = 4_995_000_000; // for example, ~49.95 BTC in sats
            let external_address = BitcoinAddress::from_str(&addr_str)?.assume_checked();
            let txid = bitcoin_rpc_client
                .send_to_address(&external_address, Amount::from_sat(amount))
                .await?
                .txid()?;

            info!(
                "Funded address {} with {} sats @ {}",
                addr_str, amount, txid
            );

            txids.push(txid);
            funded_sats += amount;
        }

        // Mine a block to confirm funding transactions if addresses were funded
        if funded_sats > 0 {
            info!("Mining a block to confirm funding transactions...");
            bitcoin_rpc_client
                .generate_to_address(1, &alice_address)
                .await?;
        }

        // ensure esplora sees the txids
        if let Some(esplora_client) = esplora_client.clone() {
            for txid in txids {
                let mut attempts = 0;
                while attempts < 25 {
                    let tx = esplora_client.get_tx_status(&txid).await?;
                    if tx.confirmed {
                        break;
                    }
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    if attempts == 25 {
                        return Err(eyre!(
                            "Failed to confirm funding transaction on esplora {}",
                            txid
                        ));
                    }
                }
            }
        }

        let devnet = BitcoinDevnet {
            data_engine,
            rpc_client: bitcoin_rpc_client.clone(),
            miner_address: alice_address,
            cookie,
            rpc_url_with_cookie: rpc_url_with_cookie.clone(),
            funded_sats,
            datadir,
            electrsd,
            esplora_client,
            esplora_url,
            regtest: bitcoin_regtest,
            bitcoin_datadir,
            bitcoin_data_engine_datadir,
            electrsd_datadir,
        };

        // Get the actual blockchain height
        let blockchain_info = bitcoin_rpc_client.get_blockchain_info().await?;
        let current_height = blockchain_info.blocks as u32;

        Ok((devnet, current_height))
    }

    async fn setup_data_engine(
        bde_db_location: DatabaseLocation,
        bitcoin_rpc_client: Arc<AsyncBitcoinClient>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<Arc<BitcoinDataEngine>> {
        let bitcoin_data_engine = BitcoinDataEngine::new(
            &bde_db_location,
            bitcoin_rpc_client,
            115,
            Duration::from_millis(250),
            join_set,
        )
        .await;

        let data_engine = Arc::new(bitcoin_data_engine);
        let t = Instant::now();
        info!("[Bitcoin Setup] Waiting for bitcoin data engine initial sync...");
        data_engine.wait_for_initial_sync().await?;
        info!(
            "[Bitcoin Setup] Bitcoin data engine initial sync complete in {:?}",
            t.elapsed()
        );
        Ok(data_engine)
    }

    async fn setup_electrsd_and_esplora(
        using_esplora: bool,
        fixed_esplora_url: bool,
        devnet_cache: Option<Arc<RiftDevnetCache>>,
        bitcoin_regtest: Arc<BitcoinRegtest>,
    ) -> Result<(
        Option<Arc<ElectrsD>>,
        Option<Arc<EsploraClient>>,
        Option<String>,
        tempfile::TempDir,
    )> {
        let esplora_start = Instant::now();
        let mut conf = electrsd::Conf::default();
        // Disable stderr logging to avoid cluttering the console
        // true can be useful for debugging
        conf.view_stderr = false;
        conf.args.push("--cors");
        conf.args.push("*");

        let electrsd_datadir = if let Some(devnet_cache) = devnet_cache {
            devnet_cache.create_electrsd_datadir().await?
        } else {
            get_new_temp_dir()?
        };

        conf.staticdir = Some(electrsd_datadir.path().to_path_buf());

        if fixed_esplora_url {
            // false to prevent the default http server from starting
            conf.http_enabled = false;
            conf.args.push("--http-addr");
            conf.args.push("0.0.0.0:50103");
        } else {
            conf.http_enabled = true;
        }

        let time = Instant::now();
        let electrsd = if using_esplora {
            info!("[Bitcoin Setup] Spawning electrsd (esplora)...");
            let exe_path = electrsd::exe_path()
                .expect("Failed to get electrs executable path, maybe it's not installed?");
            let conf_clone = conf.clone();
            let regtest_clone = bitcoin_regtest.clone();

            Some(Arc::new(
                tokio::task::spawn_blocking(move || {
                    ElectrsD::with_conf(exe_path, &regtest_clone, &conf_clone)
                })
                .await
                .map_err(|e| eyre!("Failed to spawn blocking task: {}", e))?
                .map_err(|e| eyre!("Failed to create electrsd instance: {}", e))?,
            ))
        } else {
            None
        };
        info!(
            "[Bitcoin Setup] Electrsd creation took {:?}",
            time.elapsed()
        );

        let _client_creation_start = Instant::now();
        let (esplora_client, esplora_url) = if using_esplora {
            let esplora_url = if fixed_esplora_url {
                "0.0.0.0:50103".to_string()
            } else {
                electrsd
                    .as_ref()
                    .unwrap()
                    .esplora_url
                    .clone()
                    .expect("Failed to get electrsd esplora url")
            };

            // Ensure the URL has the proper scheme
            let full_url =
                if esplora_url.starts_with("http://") || esplora_url.starts_with("https://") {
                    esplora_url
                } else {
                    format!("http://{}", esplora_url)
                };

            (
                Some(Arc::new(
                    EsploraClient::from_builder(esplora_client::Builder::new(&full_url))
                        .expect("Failed to create esplora client"),
                )),
                Some(full_url),
            )
        } else {
            (None, None)
        };

        if let Some(ref client) = esplora_client {
            let test_start = Instant::now();
            let test_resp = client.get_fee_estimates().await;
            if test_resp.is_err() {
                return Err(eyre!("Electrs client failed {}", test_resp.err().unwrap()));
            }
            info!(
                "[Bitcoin Setup] Esplora client test took {:?}",
                test_start.elapsed()
            );
        }

        if using_esplora {
            info!(
                "[Bitcoin Setup] Total esplora setup took {:?}",
                esplora_start.elapsed()
            );
        }

        Ok((electrsd, esplora_client, esplora_url, electrsd_datadir))
    }

    pub async fn mine_blocks(&self, blocks: u64) -> Result<()> {
        self.rpc_client
            .generate_to_address(blocks, &self.miner_address)
            .await?;
        Ok(())
    }

    /// Convenience method for handing out some BTC to a given address.
    pub async fn deal_bitcoin(
        &self,
        address: BitcoinAddress,
        amount: Amount,
    ) -> Result<GetRawTransactionVerbose> {
        let deal_start = Instant::now();
        info!("[Bitcoin] Dealing {} BTC to {}", amount.to_btc(), address);

        let blocks_to_mine = (amount.to_btc() / 50.0).ceil() as usize;
        let mine_start = Instant::now();
        self.mine_blocks(blocks_to_mine as u64).await?;
        info!(
            "[Bitcoin] Mined {} blocks for funding in {:?}",
            blocks_to_mine,
            mine_start.elapsed()
        );

        let send_result = self.rpc_client.send_to_address(&address, amount).await?;
        let txid = Txid::from_str(&send_result.0)?;

        let full_transaction = self.rpc_client.get_raw_transaction_verbose(&txid).await?;
        // mine the tx
        let confirm_start = Instant::now();
        self.mine_blocks(1).await?;
        info!(
            "[Bitcoin] Mined confirmation block in {:?}",
            confirm_start.elapsed()
        );

        info!(
            "[Bitcoin] Deal bitcoin completed in {:?}",
            deal_start.elapsed()
        );
        Ok(full_transaction)
    }
}
