use std::sync::Arc;
use std::{path::PathBuf, str::FromStr, time::Duration};

use bitcoin_data_engine::BitcoinDataEngine;
use bitcoincore_rpc_async::bitcoin::Txid;
use bitcoincore_rpc_async::json::GetRawTransactionResult;
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
    _regtest: Arc<BitcoinRegtest>,
}

impl BitcoinDevnet {
    /// Create and initialize a new Bitcoin regtest environment
    /// with an optional `funded_address`.
    /// Returns `(BitcoinDevnet, AsyncBitcoinClient)` so we can
    /// also have an async RPC client if needed.
    pub async fn setup(
        funded_addresses: Vec<String>,
        using_bitcoin: bool,
        using_esplora: bool,
        fixed_explora_url: bool,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<(Self, u32)> {
        if !using_bitcoin {
            assert!(
                funded_addresses.is_empty(),
                "You can't provide a funded address if you're not using Bitcoin"
            );
        }
        info!("Instantiating Bitcoin Regtest...");
        let t = Instant::now();
        let mut conf = Conf::default();
        conf.args.push("-txindex");
        let bitcoin_regtest = Arc::new(
            tokio::task::spawn_blocking(move || BitcoinRegtest::from_downloaded_with_conf(&conf))
                .await
                .map_err(|e| eyre!("Failed to spawn blocking task: {}", e))?
                .map_err(|e| eyre!(e))?,
        );
        info!("Instantiated Bitcoin Regtest in {:?}", t.elapsed());

        let datadir = bitcoin_regtest.workdir().join("regtest");

        let cookie = bitcoin_regtest.params.cookie_file.clone();

        let cookie_str = tokio::fs::read_to_string(cookie.clone()).await.unwrap();
        // http://<user>:<password>@<host>:<port>/
        let rpc_url_with_cookie = format!(
            "http://{}@{}:{}/wallet/alice",
            cookie_str,
            bitcoin_regtest.params.rpc_socket.ip(),
            bitcoin_regtest.params.rpc_socket.port()
        );

        // Create wallet "alice" for mining
        let alice_address = {
            let regtest_clone = bitcoin_regtest.clone();
            tokio::task::spawn_blocking(move || regtest_clone.create_wallet("alice"))
                .await
                .map_err(|e| eyre!("Failed to spawn blocking task: {}", e))?
                .map_err(|e| eyre!(e))?
                .new_address()?
        };

        info!(
            "Creating async Bitcoin RPC client at {}",
            rpc_url_with_cookie
        );

        let bitcoin_rpc_client: Arc<AsyncBitcoinClient> = Arc::new(
            AsyncBitcoinClient::new(
                rpc_url_with_cookie.clone(),
                Auth::CookieFile(cookie.clone()),
                Duration::from_millis(1000),
            )
            .await?,
        );

        let mine_time = Instant::now();

        bitcoin_rpc_client
            .generate_to_address(if using_bitcoin { 101 } else { 1 }, &alice_address)
            .await?;

        info!(
            "Mined {} blocks in {:?}",
            if using_bitcoin { 101 } else { 1 },
            mine_time.elapsed()
        );

        // If user wants to fund a specific BTC address
        let mut funded_sats = 0;
        for addr_str in funded_addresses {
            let amount = 4_995_000_000; // for example, ~49.95 BTC in sats
            let external_address = BitcoinAddress::from_str(&addr_str)?.assume_checked();
            bitcoin_rpc_client
                .send_to_address(
                    &external_address,
                    Amount::from_sat(amount),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
            funded_sats += amount;
        }

        let bitcoin_data_engine = BitcoinDataEngine::new(
            &DatabaseLocation::InMemory,
            bitcoin_rpc_client.clone(),
            100,
            Duration::from_millis(250),
            join_set,
        )
        .await;

        let data_engine = Arc::new(bitcoin_data_engine);
        let t = Instant::now();
        println!("Waiting for bitcoin data engine initial sync...");
        data_engine.wait_for_initial_sync().await?;
        println!(
            "Bitcoin data engine initial sync complete in {:?}",
            t.elapsed()
        );

        let mut conf = electrsd::Conf::default();
        // Disable stderr logging to avoid cluttering the console
        // true can be useful for debugging
        conf.view_stderr = false;
        conf.args.push("--cors");
        conf.args.push("*");
        if fixed_explora_url {
            // false to prevent the default http server from starting
            conf.http_enabled = false;
            conf.args.push("--http-addr");
            conf.args.push("0.0.0.0:50103");
        } else {
            conf.http_enabled = true;
        }

        let electrsd = if using_esplora {
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

        let (esplora_client, esplora_url) = if using_esplora {
            let esplora_url = if fixed_explora_url {
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
            let test_resp = client.get_fee_estimates().await;
            if test_resp.is_err() {
                return Err(eyre!("Electrs client failed {}", test_resp.err().unwrap()));
            }
        }

        let devnet = BitcoinDevnet {
            data_engine,
            rpc_client: bitcoin_rpc_client,
            miner_address: alice_address,
            cookie,
            rpc_url_with_cookie: rpc_url_with_cookie.clone(),
            funded_sats,
            datadir,
            electrsd,
            esplora_client,
            esplora_url,
            _regtest: bitcoin_regtest,
        };

        Ok((devnet, if using_bitcoin { 101 } else { 1 }))
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
    ) -> Result<GetRawTransactionResult> {
        let blocks_to_mine = (amount.to_btc() / 50.0).ceil() as usize;
        self.mine_blocks(blocks_to_mine as u64).await?;
        let txid = self
            .rpc_client
            .send_to_address(&address, amount, None, None, None, None, None, None)
            .await?;
        let full_transaction = self
            .rpc_client
            .get_raw_transaction_info(&Txid::from_str(&txid.to_string()).unwrap(), None)
            .await?;
        // mine the tx
        self.mine_blocks(1).await?;
        Ok(full_transaction)
    }
}
