//! mempoolpc-client – **async** RPC surface
//!
//! A consumer (CLI, worker, etc.) implements `call()` once (using
//! `reqwest`, `surf`, `hyper`, …).  All typed helpers below become
//! async one-liners that await that primitive.

use crate::mempool_electrs_types::{AddressOverview, AddressTxs};
use async_trait::async_trait;
use bitcoin::BlockHash;
use reqwest::{Client, Url};
use serde_json::Value;

/* --------------------------------------------------------------------- */
/* ---------------------------  error type  ---------------------------- */
/* --------------------------------------------------------------------- */

/// High-level failure bubble-up.
#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("transport error: {0}")]
    Transport(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("decode error: {0}")]
    Decode(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ClientError>;

/* --------------------------------------------------------------------- */
/* ------------------------------  trait  ------------------------------ */
/* --------------------------------------------------------------------- */

/// Thin async facade over the Mempool-Electrs REST API.
///
/// `call()` is your only obligation; everything else is derived.

// Implemented based on the API created here:
// https://github.com/mempool/electrs/blob/mempool/src/rest.rs
#[async_trait]
pub trait BaseClient: Send + Sync {
    /// Fire the request and **return the raw response body** (UTF-8).
    async fn call(
        &self,
        cmd: &str,
        args: &[Value],
    ) -> std::result::Result<String, Box<dyn std::error::Error + Send + Sync>>;

    /* -------------------------  HIGH-LEVEL  ------------------------- */

    async fn address_overview(&self, addr: &str) -> Result<AddressOverview> {
        self.get_json(&format!("address/{}", addr)).await
    }

    async fn address_txs(&self, addr: &str) -> Result<AddressTxs> {
        self.get_json(&format!("address/{}/txs", addr)).await
    }

    async fn blocks_tip_hash(&self) -> Result<BlockHash> {
        let raw = self.call("blocks/tip/hash", &[]).await?;
        let hash = raw
            .trim()
            .parse::<BlockHash>()
            .map_err(|e| ClientError::Transport(Box::new(e)))?;
        Ok(hash)
    }

    async fn blocks_tip_height(&self) -> Result<u32> {
        // Endpoint returns plain text (`123456\n`). Parse directly to u32.
        let raw = self.call("blocks/tip/height", &[]).await?;
        let height = raw
            .trim()
            .parse::<u32>()
            .map_err(|e| ClientError::Transport(Box::new(e)))?;
        Ok(height)
    }

    /* ----------------------  internal helpers  ---------------------- */

    #[doc(hidden)]
    async fn get_json<T>(&self, cmd: &str) -> Result<T>
    where
        for<'a> T: serde::de::Deserialize<'a> + Send,
    {
        let body = self.call(cmd, &[]).await?;
        let parsed = serde_json::from_str(&body)?;
        Ok(parsed)
    }
}

/// Minimal async implementation using `reqwest`.
pub struct ReqwestClient {
    pub base_url: Url,
    http: Client,
}

impl ReqwestClient {
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            http: Client::new(),
        }
    }
}
#[async_trait]
impl BaseClient for ReqwestClient {
    async fn call(
        &self,
        cmd: &str,
        _args: &[Value],
    ) -> std::result::Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}{}", self.base_url, cmd);
        let text = self
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        Ok(text)
    }
}
