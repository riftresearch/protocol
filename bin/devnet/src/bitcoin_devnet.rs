use std::sync::Arc;
use std::{path::PathBuf, str::FromStr, time::Duration};

use bitcoin_data_engine::BitcoinDataEngine;
use bitcoincore_rpc_async::bitcoin::Txid;
use bitcoincore_rpc_async::json::GetRawTransactionResult;
use eyre::{eyre, Result};
use log::info;
use rift_sdk::DatabaseLocation;
use tokio::time::Instant;

use bitcoin::{Address as BitcoinAddress, Amount};
use bitcoincore_rpc_async::Auth;
use bitcoincore_rpc_async::RpcApi;
use corepc_node::{types::GetTransaction, Client as BitcoinClient, Node as BitcoinRegtest};

use rift_sdk::bitcoin_utils::AsyncBitcoinClient;

/// Holds all Bitcoin-related devnet state.
pub struct BitcoinDevnet {
    pub bitcoin_data_engine: Arc<BitcoinDataEngine>,
    pub btc_rpc_client: Arc<AsyncBitcoinClient>,
    pub bitcoin_regtest: BitcoinRegtest,
    pub miner_client: BitcoinClient,
    pub miner_address: BitcoinAddress,
    pub cookie: PathBuf,

    /// If you optionally funded a BTC address upon startup,
    /// we keep track of the satoshis here.
    pub funded_sats: u64,
}

impl BitcoinDevnet {
    /// Create and initialize a new Bitcoin regtest environment
    /// with an optional `funded_address`.
    /// Returns `(BitcoinDevnet, AsyncBitcoinClient)` so we can
    /// also have an async RPC client if needed.
    pub fn setup(funded_address: Option<String>) -> Result<Self> {
        info!("Instantiating Bitcoin Regtest...");
        let t = Instant::now();
        let bitcoin_regtest = BitcoinRegtest::from_downloaded().map_err(|e| eyre!(e))?;
        info!("Instantiated Bitcoin Regtest in {:?}", t.elapsed());

        let cookie = bitcoin_regtest.params.cookie_file.clone();

        // Create wallet "alice" for mining
        let alice = bitcoin_regtest
            .create_wallet("alice")
            .map_err(|e| eyre!(e))?;
        let alice_address = alice.new_address()?;

        // Mine 101 blocks to get initial coinbase BTC
        bitcoin_regtest
            .client
            .generate_to_address(101, &alice_address)?;

        // If user wants to fund a specific BTC address
        let mut funded_sats = 0;
        if let Some(addr_str) = funded_address {
            funded_sats = 4_995_000_000; // for example, ~49.95 BTC in sats
            let external_address = BitcoinAddress::from_str(&addr_str)?.assume_checked();
            alice.send_to_address(&external_address, Amount::from_sat(funded_sats))?;
        }

        let bitcoin_rpc_url = bitcoin_regtest.rpc_url_with_wallet("alice");
        info!("Creating async Bitcoin RPC client at {}", bitcoin_rpc_url);

        let bitcoin_rpc_client: Arc<AsyncBitcoinClient> =
            Arc::new(futures::executor::block_on(AsyncBitcoinClient::new(
                bitcoin_rpc_url,
                Auth::CookieFile(cookie.clone()),
                Duration::from_millis(250),
            ))?);

        let bitcoin_data_engine = futures::executor::block_on(BitcoinDataEngine::new(
            DatabaseLocation::InMemory,
            bitcoin_rpc_client.clone(),
            100,
            Duration::from_millis(250),
        ));

        let devnet = BitcoinDevnet {
            bitcoin_data_engine: Arc::new(bitcoin_data_engine),
            btc_rpc_client: bitcoin_rpc_client,
            bitcoin_regtest,
            miner_client: alice,
            miner_address: alice_address,
            cookie,
            funded_sats,
        };

        Ok(devnet)
    }

    pub async fn mine_blocks(&self, blocks: usize) -> Result<()> {
        self.bitcoin_regtest
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
        self.bitcoin_regtest
            .client
            .generate_to_address(blocks_to_mine, &self.miner_address)?;
        let txid = self.miner_client.send_to_address(&address, amount)?;
        println!("TXID: {}", txid.clone().txid().unwrap());
        let full_transaction = self
            .btc_rpc_client
            .get_raw_transaction_info(
                &Txid::from_str(&txid.txid().unwrap().to_string()).unwrap(),
                None,
            )
            .await?;
        Ok(full_transaction)
    }
}
