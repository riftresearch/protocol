use alloy::signers::k256;
use bitcoincore_rpc_async::bitcoin::hashes::Hash;
use bitcoincore_rpc_async::bitcoin::BlockHeader;
use tokio::time::Instant;

use crate::errors::RiftSdkError;
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::jsonrpc::Transport;
use bitcoincore_rpc_async::jsonrpc::{Request, Response};
use bitcoincore_rpc_async::{Auth, Client as BitcoinClient, RpcApi};
use futures::stream::TryStreamExt;
use futures::{stream, StreamExt};
use sol_types::Types::DepositVault;
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client as ReqwestClient, Url};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A minimal error type for the transport.
#[derive(Debug)]
pub enum TransportError {
    Http(reqwest::Error),
    InvalidUrl(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Http(e) => write!(f, "HTTP error: {}", e),
            TransportError::InvalidUrl(e) => write!(f, "Invalid URL: {}", e),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<reqwest::Error> for TransportError {
    fn from(e: reqwest::Error) -> Self {
        TransportError::Http(e)
    }
}

/// A simple transport that uses reqwest.
#[derive(Clone)]
pub struct ReqwestTransport {
    url: Url,
    client: ReqwestClient,
    auth: Option<(String, String)>,
}

impl ReqwestTransport {
    /// Create a new transport with the given RPC URL, timeout, and optional authentication.
    pub fn new(
        rpc_url: &str,
        timeout: Duration,
        auth: Option<(String, String)>,
    ) -> Result<Self, TransportError> {
        let client = ReqwestClient::builder()
            .timeout(timeout)
            .build()
            .map_err(TransportError::Http)?;
        let url = rpc_url
            .parse::<Url>()
            .map_err(|e| TransportError::InvalidUrl(e.to_string()))?;
        Ok(ReqwestTransport { url, client, auth })
    }
}

impl From<TransportError> for bitcoincore_rpc_async::jsonrpc::Error {
    fn from(e: TransportError) -> Self {
        use bitcoincore_rpc_async::jsonrpc::error::RpcError;
        bitcoincore_rpc_async::jsonrpc::Error::Rpc(RpcError {
            code: -32603,
            message: e.to_string(),
            data: None,
        })
    }
}

// Then update the Transport implementation to map the errors
#[async_trait]
impl Transport for ReqwestTransport {
    async fn send_request(
        &self,
        req: Request<'_>,
    ) -> Result<Response, bitcoincore_rpc_async::jsonrpc::Error> {
        let mut request = self.client.post(self.url.clone()).json(&req);

        if let Some((user, pass)) = &self.auth {
            request = request.basic_auth(user, Some(pass));
        }

        // TODO: aint no way this map chain is correct
        request
            .send()
            .await
            .map_err(TransportError::Http)?
            .error_for_status()
            .map_err(TransportError::Http)?
            .json::<Response>()
            .await
            .map_err(TransportError::Http)
            .map_err(Into::into)
    }

    async fn send_batch(
        &self,
        reqs: &[Request<'_>],
    ) -> Result<Vec<Response>, bitcoincore_rpc_async::jsonrpc::Error> {
        let mut request = self.client.post(self.url.clone()).json(reqs);

        if let Some((user, pass)) = &self.auth {
            request = request.basic_auth(user, Some(pass));
        }

        request
            .send()
            .await
            .map_err(TransportError::Http)?
            .error_for_status()
            .map_err(TransportError::Http)?
            .json::<Vec<Response>>()
            .await
            .map_err(TransportError::Http)
            .map_err(Into::into)
    }

    fn fmt_target(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}

pub trait AuthExt {
    fn get_user_pass(self) -> bitcoincore_rpc_async::Result<Option<(String, String)>>;
}

impl AuthExt for Auth {
    fn get_user_pass(self) -> bitcoincore_rpc_async::Result<Option<(String, String)>> {
        use bitcoincore_rpc_async::Error;
        use std::fs::File;
        use std::io::Read;
        match self {
            Auth::None => Ok(None),
            Auth::UserPass(u, p) => Ok(Some((u, p))),
            Auth::CookieFile(path) => {
                let mut file = File::open(path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let mut split = contents.splitn(2, ":");
                let u = split.next().ok_or(Error::InvalidCookieFile)?.into();
                let p = split.next().ok_or(Error::InvalidCookieFile)?.into();
                Ok(Some((u, p)))
            }
        }
    }
}

pub struct AsyncBitcoinClient {
    client: BitcoinClient,
}

// wrapper over the bitcoincore_rpc_async client w/ explicit timeout and retry logic
impl AsyncBitcoinClient {
    pub async fn new(
        rpc_url: String,
        auth: Auth,
        timeout: Duration,
    ) -> bitcoincore_rpc_async::Result<Self> {
        let auth_credentials = auth.get_user_pass()?;
        let transport = ReqwestTransport::new(&rpc_url, timeout, auth_credentials)
            .map_err(|e| bitcoincore_rpc_async::Error::JsonRpc(e.into()))?;

        let json_rpc_client =
            bitcoincore_rpc_async::jsonrpc::client::Client::with_transport(transport);

        let client = BitcoinClient::from_jsonrpc(json_rpc_client);
        Ok(Self { client })
    }
}

const RETRY_ATTEMPTS: u8 = 10;
const INTERVAL: u64 = 100;

#[async_trait::async_trait]
impl RpcApi for AsyncBitcoinClient {
    async fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> bitcoincore_rpc_async::Result<T> {
        for _ in 0..RETRY_ATTEMPTS {
            match self.client.call(cmd, args).await {
                Ok(ret) => return Ok(ret),
                Err(bitcoincore_rpc_async::Error::JsonRpc(
                    bitcoincore_rpc_async::jsonrpc::error::Error::Rpc(ref rpcerr),
                )) if rpcerr.code == -32603 => {
                    // TODO: Use async sleep
                    ::std::thread::sleep(::std::time::Duration::from_millis(INTERVAL));
                    println!("Retrying RPC call: {:?}", rpcerr);
                    continue;
                }
                Err(e) => {
                    eprintln!("Error calling RPC: {:?}", e);
                    return Err(e);
                }
            }
        }
        self.client.call(cmd, args).await
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainTip {
    /// Block height of the chain tip
    pub height: u32,
    /// Block hash of the chain tip
    pub hash: bitcoincore_rpc_async::bitcoin::BlockHash,
    /// Length of the branch (0 for main chain)
    pub branchlen: u32,
    /// Status of the chain tip: "active", "valid-fork", "valid-headers", "headers-only", or "invalid"
    pub status: ChainTipStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ChainTipStatus {
    /// The current best chain tip
    Active,
    /// Valid chain but not the best chain
    ValidFork,
    /// Valid headers but missing block data
    ValidHeaders,
    /// Headers only, validity not checked
    HeadersOnly,
    /// Invalid chain
    Invalid,
}

impl fmt::Display for ChainTipStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainTipStatus::Active => write!(f, "active"),
            ChainTipStatus::ValidFork => write!(f, "valid-fork"),
            ChainTipStatus::ValidHeaders => write!(f, "valid-headers"),
            ChainTipStatus::HeadersOnly => write!(f, "headers-only"),
            ChainTipStatus::Invalid => write!(f, "invalid"),
        }
    }
}

#[async_trait::async_trait]
pub trait BitcoinClientExt {
    async fn get_leaves_from_block_range(
        &self,
        start_block_height: u32,
        end_block_height: u32,
        concurrency_limit: Option<usize>,
    ) -> crate::errors::Result<Vec<BlockLeaf>>;

    async fn get_headers_from_block_range(
        &self,
        start_block_height: u32,
        end_block_height: u32,
        concurrency_limit: Option<usize>,
    ) -> crate::errors::Result<Vec<BlockHeader>>;

    async fn get_chain_tips(&self) -> crate::errors::Result<Vec<ChainTip>>;
}

// TODO: Use RPC batched requests for much faster throughput
#[async_trait::async_trait]
impl BitcoinClientExt for AsyncBitcoinClient {
    async fn get_chain_tips(&self) -> crate::errors::Result<Vec<ChainTip>> {
        let chain_tips = self.call("getchaintips", &[]).await.map_err(|e| {
            RiftSdkError::BitcoinRpcError(format!("Error getting chain tips: {}", e))
        })?;
        Ok(chain_tips)
    }

    async fn get_leaves_from_block_range(
        &self,
        start_block_height: u32,
        end_block_height: u32,
        concurrency_limit: Option<usize>,
    ) -> crate::errors::Result<Vec<BlockLeaf>> {
        // Set to max concurrency limit if not provided.
        let concurrency_limit =
            concurrency_limit.unwrap_or((end_block_height - start_block_height) as usize);

        // Create a stream of block heights.
        let block_heights = start_block_height..=end_block_height;
        let leaves_stream = futures::stream::iter(block_heights).map(|height| async move {
            let t = Instant::now();

            println!("[a.1] Getting block hash for height {:?}", height);
            let block_hash = self.get_block_hash(height as u64).await;
            println!("[a.2] Got block hash for height {:?}", height);
            let block_hash = block_hash.map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!(
                    "Error getting block hash for height {} {}",
                    height, e
                ))
            })?;
            println!("[a.3] Got block hash for height {:?}", height);

            let t = Instant::now();
            let block = self.get_block_header_info(&block_hash).await;
            println!("[a.4] Got block header info for height {:?}", height);
            // TODO: Include checks that the previous block hash in the MMR is the same as the previous block hash in the first block header
            let block = block.map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!(
                    "Error getting block header info for height {} {}",
                    height, e
                ))
            })?;
            println!("[a.5] Got block header info for height {:?}", height);
            let block_hash: [u8; 32] = block_hash.as_hash().into_inner();
            let chainwork: [u8; 32] = block
                .chainwork
                .as_slice()
                .try_into()
                .expect("Chainwork is not 32 bytes");
            let leaf = BlockLeaf::new(block_hash, height, chainwork);
            println!("[a.6] Got block leaf for height {:?}", height);
            Ok::<_, RiftSdkError>(leaf)
        });
        println!("[a.01]");

        println!(
            "[a.02] Getting block leaves length {}",
            futures::stream::iter(start_block_height..=end_block_height)
                .count()
                .await
        );

        let leaves = leaves_stream
            .buffer_unordered(concurrency_limit)
            .try_collect::<Vec<BlockLeaf>>()
            .await?;
        println!("[a.03] Got block leaves length {:?}", leaves.len());
        Ok(leaves)
    }

    async fn get_headers_from_block_range(
        &self,
        start_block_height: u32,
        end_block_height: u32,
        concurrency_limit: Option<usize>,
    ) -> crate::errors::Result<Vec<BlockHeader>> {
        // Set to max concurrency limit if not provided.
        let concurrency_limit =
            concurrency_limit.unwrap_or((end_block_height - start_block_height) as usize);

        // Create a stream of block heights.
        let block_heights = start_block_height..=end_block_height;
        let leaves_stream = futures::stream::iter(block_heights).map(|height| async move {
            let t = Instant::now();

            let block_hash = self.get_block_hash(height as u64).await;
            let block_hash = block_hash.map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!(
                    "Error getting block hash for height {} {}",
                    height, e
                ))
            })?;

            let t = Instant::now();
            let header = self.get_block_header(&block_hash).await;
            // TODO: Include checks that the previous block hash in the MMR is the same as the previous block hash in the first block header
            let header = header.map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!(
                    "Error getting block header info for height {} {}",
                    height, e
                ))
            })?;

            Ok::<_, RiftSdkError>(header)
        });

        leaves_stream
            .buffer_unordered(concurrency_limit)
            .try_collect::<Vec<BlockHeader>>()
            .await
    }
}
