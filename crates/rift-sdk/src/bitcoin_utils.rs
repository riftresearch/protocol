use alloy::signers::k256;
use bitcoincore_rpc_async::bitcoin::block::Header;
use bitcoincore_rpc_async::bitcoin::hashes::hex::FromHex;
use bitcoincore_rpc_async::bitcoin::hashes::Hash;
use bitcoincore_rpc_async::bitcoin::{Block, BlockHash};
use bitcoincore_rpc_async::json::{GetBlockHeaderResult, GetBlockResult};
use serde_json::value::RawValue;
use tokio::time::Instant;
use tracing::info;

use crate::errors::RiftSdkError;
use backoff::future::retry;
use backoff::Error as BackoffError;
use backoff::ExponentialBackoff;
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::jsonrpc::Transport;
use bitcoincore_rpc_async::jsonrpc::{Request, Response};
use bitcoincore_rpc_async::{Auth, Client as BitcoinClient, RpcApi};
use futures::stream::TryStreamExt;
use futures::Future;
use futures::{stream, StreamExt};
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client as ReqwestClient, Url};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::marker::PhantomData;

// arbitrary error code for transport errors that doesn't collide with bitcoin rpc error codes
const TRANSPORT_ERROR_CODE: i32 = -32001;

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
            code: TRANSPORT_ERROR_CODE,
            message: e.to_string(),
            data: None,
        })
    }
}

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

struct BitcoinCoreJsonRpcRequest<T> {
    method: &'static str,
    args: Vec<serde_json::Value>,
    response_type: PhantomData<T>,
}

async fn retry_rpc_operation<T, F, Fut>(operation: F) -> bitcoincore_rpc_async::Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = bitcoincore_rpc_async::Result<T>>,
{
    let backoff = ExponentialBackoff {
        initial_interval: Duration::from_millis(100),
        max_interval: Duration::from_secs(10),
        max_elapsed_time: Some(Duration::from_secs(30)),
        ..Default::default()
    };

    retry(backoff, || async {
        let res = operation().await;
        match res {
            Ok(val) => Ok(val),
            Err(e) => match e {
                bitcoincore_rpc_async::Error::JsonRpc(
                    bitcoincore_rpc_async::jsonrpc::error::Error::Rpc(ref rpcerr),
                ) if rpcerr.code == -32603 => {
                    info!("Retrying RPC call due to error: {:?}", rpcerr);
                    Err(BackoffError::transient(e))
                }
                bitcoincore_rpc_async::Error::JsonRpc(
                    bitcoincore_rpc_async::jsonrpc::error::Error::Rpc(ref rpcerr),
                ) if rpcerr.code == TRANSPORT_ERROR_CODE => {
                    tracing::error!("Caught transport error: {:?}", rpcerr);
                    Err(BackoffError::permanent(e))
                }
                _ => {
                    info!("RPC error: {:?}", e);
                    Err(BackoffError::permanent(e))
                }
            },
        }
    })
    .await
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

    async fn send_batch<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        requests: &[BitcoinCoreJsonRpcRequest<T>],
        batch_size: Option<usize>,
    ) -> bitcoincore_rpc_async::Result<Vec<T>> {
        let batch_size = batch_size.unwrap_or(requests.len());
        let json_rpc_client = self.client.get_jsonrpc_client();
        let mut results = Vec::with_capacity(requests.len());

        // Process requests in chunks of batch_size
        for chunk in requests.chunks(batch_size) {
            // First pass: build and store all owned argument vectors for this chunk
            let mut v_args_store: Vec<Vec<Box<RawValue>>> = Vec::with_capacity(chunk.len());
            for request in chunk {
                let v_args: Vec<Box<RawValue>> = request
                    .args
                    .iter()
                    .map(serde_json::value::to_raw_value)
                    .collect::<std::result::Result<_, serde_json::Error>>()?;
                v_args_store.push(v_args);
            }

            // Second pass: build the request data using the stored v_args
            let mut request_data: Vec<Request<'_>> = Vec::with_capacity(chunk.len());
            for (i, request) in chunk.iter().enumerate() {
                let args_slice: &[Box<RawValue>] = v_args_store[i].as_slice();
                let req = json_rpc_client.build_request(request.method, args_slice);
                request_data.push(req);
            }

            // Send this batch chunk
            let responses = retry_rpc_operation(|| async {
                json_rpc_client
                    .send_batch(&request_data)
                    .await
                    .map_err(|e| bitcoincore_rpc_async::Error::JsonRpc(e.into()))
            })
            .await?;

            // Process responses for this chunk
            for (i, response) in responses.iter().enumerate() {
                let result = response
                    .as_ref()
                    .ok_or(bitcoincore_rpc_async::Error::JsonRpc(
                        bitcoincore_rpc_async::jsonrpc::error::Error::EmptyBatch,
                    ))?
                    .result::<T>()
                    .map_err(|e| bitcoincore_rpc_async::Error::JsonRpc(e.into()))?;
                results.push(result);
            }
        }

        Ok(results)
    }
}

#[async_trait::async_trait]
impl RpcApi for AsyncBitcoinClient {
    async fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> bitcoincore_rpc_async::Result<T> {
        retry_rpc_operation(|| async { self.client.call(cmd, args).await }).await
    }
}

pub trait HeaderChainValidator {
    fn validate_header_chain(&self) -> Result<(), RiftSdkError>;
}

impl HeaderChainValidator for Vec<Header> {
    fn validate_header_chain(&self) -> Result<(), RiftSdkError> {
        for i in 1..self.len() {
            if self[i].prev_blockhash != self[i - 1].block_hash() {
                return Err(RiftSdkError::HeaderChainValidationFailed);
            }
        }
        Ok(())
    }
}

impl HeaderChainValidator for Vec<GetBlockHeaderResult> {
    fn validate_header_chain(&self) -> Result<(), RiftSdkError> {
        for i in 1..self.len() {
            if self[i].previous_block_hash.unwrap() != self[i - 1].hash {
                return Err(RiftSdkError::HeaderChainValidationFailed);
            }
        }
        Ok(())
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
    // Sorted
    async fn get_leaves_from_block_range(
        &self,
        start_block_height: u32,
        end_block_height: u32,
        concurrency_limit: usize,
        expected_parent: Option<[u8; 32]>,
    ) -> crate::errors::Result<Vec<BlockLeaf>>;

    // sorted
    async fn get_headers_from_block_range(
        &self,
        start_block_height: u32,
        end_block_height: u32,
        concurrency_limit: usize,
        expected_parent: Option<[u8; 32]>,
    ) -> crate::errors::Result<Vec<Header>>;

    // unsorted
    async fn get_blocks_from_leaves(
        &self,
        leaves: &[BlockLeaf],
        concurrency_limit: usize,
    ) -> crate::errors::Result<Vec<Block>>;

    async fn get_chain_tips(&self) -> crate::errors::Result<Vec<ChainTip>>;
    async fn get_block_header_by_height(&self, height: u32) -> crate::errors::Result<Header>;
    async fn get_block_header_info_by_height(
        &self,
        height: u32,
    ) -> crate::errors::Result<GetBlockHeaderResult>;

    async fn find_oldest_block_before_timestamp(
        &self,
        target_timestamp: u64,
    ) -> crate::errors::Result<u32>;

    async fn get_headers_from_hashes(
        &self,
        hashes: &[BlockHash],
        concurrency_limit: usize,
    ) -> crate::errors::Result<Vec<Header>>;
}

#[async_trait::async_trait]
impl BitcoinClientExt for AsyncBitcoinClient {
    async fn get_block_header_info_by_height(
        &self,
        height: u32,
    ) -> crate::errors::Result<GetBlockHeaderResult> {
        let block_hash = self.get_block_hash(height as u64).await.map_err(|e| {
            RiftSdkError::BitcoinRpcError(format!(
                "Error getting block hash for height {}: {}",
                height, e
            ))
        })?;

        let header = self.get_block_header_info(&block_hash).await.map_err(|e| {
            RiftSdkError::BitcoinRpcError(format!(
                "Error getting block header info for height {}: {}",
                height, e
            ))
        })?;

        Ok(header)
    }

    /// Finds the oldest Bitcoin block whose mediantime is less than the target timestamp
    /// using binary search.
    async fn find_oldest_block_before_timestamp(
        &self,
        target_timestamp: u64,
    ) -> crate::errors::Result<u32> {
        let tip_height = self.get_block_count().await.map_err(|e| {
            RiftSdkError::BitcoinRpcError(format!("Error getting block count: {}", e))
        })?;

        let mut left = 0;
        let mut right = tip_height;

        while left < right {
            let mid = left + (right - left) / 2;
            let block = self.get_block_header_info_by_height(mid as u32).await?;
            let block_time = block.median_time.ok_or_else(|| {
                RiftSdkError::BitcoinRpcError(format!("Block {} has no median time", mid))
            })? as u64;

            if block_time >= target_timestamp {
                right = mid;
            } else {
                left = mid + 1;
            }
        }

        // Step back one block to ensure we're before the timestamp
        left = left.saturating_sub(1);

        // Verify we found a valid block
        let found_block = self.get_block_header_info_by_height(left as u32).await?;
        let found_block_time = found_block.median_time.ok_or_else(|| {
            RiftSdkError::BitcoinRpcError(format!("Block {} has no median time", left))
        })? as u64;

        if found_block_time >= target_timestamp {
            return Err(RiftSdkError::BitcoinRpcError(format!(
                "No bitcoin block found with mediantime before timestamp {}",
                target_timestamp
            )));
        }

        Ok(left as u32)
    }

    async fn get_headers_from_hashes(
        &self,
        hashes: &[BlockHash],
        concurrency_limit: usize,
    ) -> crate::errors::Result<Vec<Header>> {
        use bitcoincore_rpc_async::bitcoin::consensus::encode::deserialize;
        use bitcoincore_rpc_async::bitcoin::hashes::hex::FromHex;

        // Build a batched JSON-RPC request for each hash using "getblockheader" (verbose=false)
        let requests: Vec<BitcoinCoreJsonRpcRequest<String>> = hashes
            .iter()
            .map(|block_hash| BitcoinCoreJsonRpcRequest {
                method: "getblockheader",
                args: vec![
                    serde_json::json!(block_hash.to_string()),
                    serde_json::json!(false), // verbose = false => hex-encoded header
                ],
                response_type: PhantomData,
            })
            .collect();

        // Send the batch. Passing `None` means "send them all in one or more batches",
        // but you can also supply `Some(concurrency_limit)` if you want chunked concurrency.
        let raw_headers: Vec<String> = self
            .send_batch(&requests, Some(concurrency_limit))
            .await
            .map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!(
                    "Error fetching block headers by hash: {}",
                    e
                ))
            })?;

        // Decode the hex-encoded headers into `Header` structs
        let mut block_headers = Vec::with_capacity(raw_headers.len());
        for raw in raw_headers {
            let bytes = Vec::from_hex(&raw).map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!("Error decoding block header hex: {}", e))
            })?;
            let header: Header = deserialize(&bytes).map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!("Error deserializing block header: {}", e))
            })?;
            block_headers.push(header);
        }

        Ok(block_headers)
    }

    async fn get_block_header_by_height(&self, height: u32) -> crate::errors::Result<Header> {
        let block_hash = self.get_block_hash(height as u64).await.map_err(|e| {
            RiftSdkError::BitcoinRpcError(format!(
                "Error getting block hash for height {}: {}",
                height, e
            ))
        })?;

        let header = self.get_block_header(&block_hash).await.map_err(|e| {
            RiftSdkError::BitcoinRpcError(format!(
                "Error getting block header for height {}: {}",
                height, e
            ))
        })?;

        Ok(header)
    }
    async fn get_chain_tips(&self) -> crate::errors::Result<Vec<ChainTip>> {
        let chain_tips = self.call("getchaintips", &[]).await.map_err(|e| {
            RiftSdkError::BitcoinRpcError(format!("Error getting chain tips: {}", e))
        })?;
        Ok(chain_tips)
    }

    async fn get_blocks_from_leaves(
        &self,
        leaves: &[BlockLeaf],
        concurrency_limit: usize,
    ) -> crate::errors::Result<Vec<Block>> {
        let block_hashes: Vec<[u8; 32]> = leaves.iter().map(|leaf| leaf.block_hash).collect();

        let blocks_requests: Vec<BitcoinCoreJsonRpcRequest<String>> = block_hashes
            .iter()
            .map(|block_hash| BitcoinCoreJsonRpcRequest {
                method: "getblock",
                args: vec![
                    serde_json::json!(hex::encode(block_hash)),
                    0.into(), // verbosity 0 => hex-encoded block
                ],
                response_type: PhantomData,
            })
            .collect();

        let blocks: Vec<String> = self
            .send_batch(&blocks_requests, Some(concurrency_limit))
            .await
            .map_err(|e| RiftSdkError::BitcoinRpcError(format!("Error getting blocks: {}", e)))?;

        let blocks: Vec<Block> = blocks
            .iter()
            .map(|block| {
                let bytes: Vec<u8> = FromHex::from_hex(block).map_err(|e| {
                    RiftSdkError::BitcoinRpcError(format!("Error decoding block: {}", e))
                })?;
                bitcoincore_rpc_async::bitcoin::consensus::encode::deserialize(&bytes).map_err(
                    |e| RiftSdkError::BitcoinRpcError(format!("Error deserializing block: {}", e)),
                )
            })
            .collect::<Result<Vec<Block>, RiftSdkError>>()?;
        Ok(blocks)
    }

    async fn get_leaves_from_block_range(
        &self,
        start_block_height: u32,
        end_block_height: u32,
        concurrency_limit: usize,
        expected_parent: Option<[u8; 32]>,
    ) -> crate::errors::Result<Vec<BlockLeaf>> {
        // Calculate number of blocks to fetch.
        let num_blocks = (end_block_height - start_block_height + 1) as usize;

        // ===============================================================
        // Batch 1: For each height, get the block hash.
        // ===============================================================
        let hash_requests: Vec<BitcoinCoreJsonRpcRequest<BlockHash>> = (start_block_height
            ..=end_block_height)
            .map(|height| BitcoinCoreJsonRpcRequest {
                method: "getblockhash",
                args: vec![serde_json::json!(height)],
                response_type: PhantomData,
            })
            .collect();

        let block_hashes: Vec<BlockHash> = self
            .send_batch(&hash_requests, Some(concurrency_limit))
            .await
            .map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!("Error getting block hashes: {}", e))
            })?;

        // ===============================================================
        // Batch 2: For each block hash, get the block header info.
        // ===============================================================
        let header_requests: Vec<BitcoinCoreJsonRpcRequest<GetBlockHeaderResult>> = block_hashes
            .iter()
            .map(|block_hash| BitcoinCoreJsonRpcRequest {
                method: "getblockheader",
                // assuming the RPC takes a hex string for the block hash
                args: vec![serde_json::json!(block_hash.to_string()), true.into()],
                response_type: PhantomData,
            })
            .collect();

        let header_results: Vec<GetBlockHeaderResult> = self
            .send_batch(&header_requests, Some(concurrency_limit))
            .await
            .map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!("Error getting block header info: {}", e))
            })?;

        // ===============================================================
        // Build our result vector from the block hashes and headers.
        // ===============================================================
        let mut results = Vec::with_capacity(num_blocks);
        for i in 0..num_blocks {
            let height = start_block_height + i as u32;
            let block_hash = &block_hashes[i];
            let header = &header_results[i];

            // Convert block hash to an array of 32 bytes and reverse (as in your original code)
            let mut explorer_block_hash: [u8; 32] = block_hash.as_raw_hash().to_byte_array();
            explorer_block_hash.reverse();

            // Extract chainwork from header (expecting exactly 32 bytes)
            let chainwork: [u8; 32] = header
                .chainwork
                .as_slice()
                .try_into()
                .expect("Chainwork is not 32 bytes");

            let leaf = BlockLeaf::new(explorer_block_hash, height, chainwork);
            // Note: if GetHeaderResult isn't Copy, you may need to clone it.
            results.push((height, leaf, header.clone()));
        }

        // Sort by height (if necessary)
        results.sort_by_key(|(height, _, _)| *height);

        // Unzip into separate vectors (if you need headers for validation)
        let (leaves, headers): (Vec<BlockLeaf>, Vec<GetBlockHeaderResult>) = results
            .into_iter()
            .map(|(_height, leaf, header)| (leaf, header))
            .unzip();

        // ===============================================================
        // Validation: Check the expected parent, if provided.
        // ===============================================================
        if let Some(expected_parent) = expected_parent {
            let first_prev = headers[0]
                .previous_block_hash
                .as_ref()
                .ok_or_else(|| {
                    RiftSdkError::ParentValidationFailed("Missing previous block hash".to_string())
                })?
                .as_raw_hash()
                .to_byte_array();

            // Reverse the byte order
            let first_prev_rev: Vec<u8> = first_prev.iter().rev().copied().collect();

            if first_prev_rev != expected_parent {
                return Err(RiftSdkError::ParentValidationFailed(format!(
                    "Expected parent {} but got {} from downloaded block",
                    hex::encode(expected_parent),
                    hex::encode(first_prev)
                )));
            }
        }

        headers.validate_header_chain()?;
        Ok(leaves)
    }

    async fn get_headers_from_block_range(
        &self,
        start_block_height: u32,
        end_block_height: u32,
        concurrency_limit: usize,
        expected_parent: Option<[u8; 32]>,
    ) -> crate::errors::Result<Vec<Header>> {
        // Number of blocks in the requested range
        let num_blocks = (end_block_height - start_block_height + 1) as usize;

        // ===============================
        // Batch #1: getblockhash
        // ===============================
        let hash_requests: Vec<BitcoinCoreJsonRpcRequest<BlockHash>> = (start_block_height
            ..=end_block_height)
            .map(|height| BitcoinCoreJsonRpcRequest {
                method: "getblockhash",
                args: vec![serde_json::json!(height)],
                response_type: PhantomData,
            })
            .collect();

        let block_hashes: Vec<BlockHash> = self
            .send_batch(&hash_requests, Some(concurrency_limit))
            .await
            .map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!("Error fetching block hashes: {}", e))
            })?;

        // ===============================
        // Batch #2: getblockheader (verbose=false)
        //
        // This returns the **hex-encoded** serialized block header.
        // We can parse that into `Header` using Bitcoin's consensus_decode.
        // ===============================
        let header_requests: Vec<BitcoinCoreJsonRpcRequest<String>> = block_hashes
            .iter()
            .map(|block_hash| BitcoinCoreJsonRpcRequest {
                method: "getblockheader",
                args: vec![
                    serde_json::json!(block_hash.to_string()),
                    serde_json::json!(false), // verbose = false => returns hex
                ],
                response_type: PhantomData,
            })
            .collect();

        let headers: Vec<Header> = self
            .send_batch(&header_requests, Some(concurrency_limit))
            .await
            .map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!("Error fetching block headers: {}", e))
            })?
            .iter()
            .map(|header| {
                let bytes: Vec<u8> = FromHex::from_hex(header).unwrap();
                bitcoincore_rpc_async::bitcoin::consensus::encode::deserialize(&bytes)
            })
            .collect::<Result<Vec<Header>, bitcoincore_rpc_async::bitcoin::consensus::encode::Error>>()
            .map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!("Error deserializing block headers: {}", e))
            })?;

        // ===============================
        // Parse each hex string into a Header
        // ===============================
        let mut headers_with_height = Vec::with_capacity(num_blocks);
        for (i, header) in headers.into_iter().enumerate() {
            let height = start_block_height + i as u32;

            headers_with_height.push((height, header));
        }

        // Sort by height (just to be sure we're in ascending order)
        headers_with_height.sort_by_key(|(h, _)| *h);

        // Unzip the vector of (height, header) into just the headers
        let headers: Vec<Header> = headers_with_height
            .into_iter()
            .map(|(_, header)| header)
            .collect();

        // =================================================
        // Check the expected parent if provided
        // =================================================
        if let Some(expected_parent) = expected_parent {
            let actual_parent = headers[0].prev_blockhash;
            // The internal byte order of `BlockHash` is reversed vs typical hex.
            // If your `expected_parent` is already reversed, compare directly:
            if actual_parent.as_raw_hash().to_byte_array() != expected_parent {
                return Err(RiftSdkError::ParentValidationFailed(format!(
                    "Expected parent {} but got {} for the first header",
                    hex::encode(expected_parent),
                    hex::encode(actual_parent.as_raw_hash().to_byte_array())
                )));
            }
        }

        // =================================================
        // Validate that each header references the previous block
        // =================================================
        headers.validate_header_chain()?;

        Ok(headers)
    }
}
