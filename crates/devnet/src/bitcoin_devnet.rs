use std::sync::Arc;
use std::{path::PathBuf, str::FromStr, time::Duration};

use bitcoin_data_engine::BitcoinDataEngine;
use bitcoincore_rpc_async::bitcoin::Txid;
use bitcoincore_rpc_async::json::GetRawTransactionResult;
use corepc_node::Conf;
use eyre::{eyre, Result};
use log::info;
use reqwest::Url;
use rift_sdk::DatabaseLocation;
use tokio::task::JoinSet;
use tokio::time::Instant;

use bitcoin::{Address as BitcoinAddress, Amount};
use bitcoincore_rpc_async::Auth;
use bitcoincore_rpc_async::RpcApi;
use corepc_node::{Client as BitcoinClient, Node as BitcoinRegtest};
use electrsd::{downloaded_exe_path, Conf as ElectrsConf, ElectrsD};
use esplora_client::AsyncClient as EsploraClient;

use rift_sdk::bitcoin_utils::AsyncBitcoinClient;

use crate::TokenizedBTC::configureMinterCall;

/// Holds all Bitcoin-related devnet state.
pub struct BitcoinDevnet {
    pub data_engine: Arc<BitcoinDataEngine>,
    pub rpc_client: Arc<AsyncBitcoinClient>,
    pub regtest: BitcoinRegtest,
    pub miner_client: BitcoinClient,
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
        let bitcoin_regtest =
            BitcoinRegtest::from_downloaded_with_conf(&conf).map_err(|e| eyre!(e))?;
        info!("Instantiated Bitcoin Regtest in {:?}", t.elapsed());

        let cookie = bitcoin_regtest.params.cookie_file.clone();

        // Create wallet "alice" for mining
        let alice = bitcoin_regtest
            .create_wallet("alice")
            .map_err(|e| eyre!(e))?;
        let alice_address = alice.new_address()?;

        let mine_time = Instant::now();
        // Mine 101 blocks to get initial coinbase BTC
        bitcoin_regtest
            .client
            .generate_to_address(if using_bitcoin { 101 } else { 1 }, &alice_address)?;

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
            alice.send_to_address(&external_address, Amount::from_sat(amount))?;
            funded_sats += amount;
        }

        let bitcoin_rpc_url = bitcoin_regtest.rpc_url_with_wallet("alice");
        info!("Creating async Bitcoin RPC client at {}", bitcoin_rpc_url);

        let bitcoin_rpc_client: Arc<AsyncBitcoinClient> = Arc::new(
            AsyncBitcoinClient::new(
                bitcoin_rpc_url,
                Auth::CookieFile(cookie.clone()),
                Duration::from_millis(250),
            )
            .await?,
        );

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
            Some(Arc::new(
                ElectrsD::with_conf(
                    electrsd::exe_path()
                        .expect("Failed to get electrs executable path, maybe it's not installed?"),
                    &bitcoin_regtest,
                    &conf,
                )
                .expect("Failed to create electrsd instance"),
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

        let cookie_str = std::fs::read_to_string(cookie.clone()).unwrap();
        // http://<user>:<password>@<host>:<port>/
        let rpc_url_with_cookie = format!(
            "http://{}@{}:{}",
            cookie_str,
            bitcoin_regtest.params.rpc_socket.ip(),
            bitcoin_regtest.params.rpc_socket.port()
        );
        let datadir = bitcoin_regtest.workdir().join("regtest");
        let devnet = BitcoinDevnet {
            data_engine,
            rpc_client: bitcoin_rpc_client,
            regtest: bitcoin_regtest,
            miner_client: alice,
            miner_address: alice_address,
            cookie,
            rpc_url_with_cookie,
            funded_sats,
            datadir,
            electrsd,
            esplora_client,
            esplora_url,
        };

        Ok((devnet, if using_bitcoin { 101 } else { 1 }))
    }

    pub async fn mine_blocks(&self, blocks: usize) -> Result<()> {
        self.regtest
            .client
            .generate_to_address(blocks, &self.miner_address)?;
        Ok(())
    }

    /// Convenience method for handing out some BTC to a given address.
    pub async fn deal_bitcoin(
        &self,
        address: BitcoinAddress,
        amount: Amount,
    ) -> Result<GetRawTransactionResult> {
        let blocks_to_mine = (amount.to_btc() / 50.0).ceil() as usize;
        self.regtest
            .client
            .generate_to_address(blocks_to_mine, &self.miner_address)?;
        let txid = self.miner_client.send_to_address(&address, amount)?;
        let full_transaction = self
            .rpc_client
            .get_raw_transaction_info(
                &Txid::from_str(&txid.txid().unwrap().to_string()).unwrap(),
                None,
            )
            .await?;
        // mine the tx
        self.regtest
            .client
            .generate_to_address(1, &self.miner_address)?;
        Ok(full_transaction)
    }
}
