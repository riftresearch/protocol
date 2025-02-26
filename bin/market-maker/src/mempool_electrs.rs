use eyre::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Represents an Electrum server client
pub struct MempoolElectrsClient {
    client: reqwest::Client,
    url: String,
    request_id: Arc<Mutex<u64>>,
}

/// Represents a UTXO (Unspent Transaction Output)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub status: TxStatus,
    pub value: u64,
}

/// Represents a transaction status
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TxStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: u32,
    #[serde(default = "empty_string")]
    pub block_hash: String,
    #[serde(default)]
    pub block_time: u64,
}

// Helper function to provide default empty string
fn empty_string() -> String {
    String::new()
}

impl MempoolElectrsClient {
    /// Creates a new Electrum client connected to the specified server URL
    pub fn new(url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.to_string(),
            request_id: Arc::new(Mutex::new(0)),
        }
    }

    /// Gets the next request ID for JSON-RPC calls
    async fn next_id(&self) -> u64 {
        let mut id = self.request_id.lock().await;
        *id += 1;
        *id
    }

    /// Gets all UTXOs for a given address
    pub async fn get_address_utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        let url = format!("{}/api/address/{}/utxo", self.url, address);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(eyre::eyre!(
                "Failed to get UTXOs: HTTP {}",
                response.status()
            ));
        }

        let body = response.text().await?;

        let utxos: Vec<Utxo> = serde_json::from_str(&body)?;

        Ok(utxos)
    }
}
