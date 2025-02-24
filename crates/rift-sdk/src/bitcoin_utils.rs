use alloy::signers::k256;
use bitcoincore_rpc_async::bitcoin::hashes::hex::FromHex;
use bitcoincore_rpc_async::bitcoin::hashes::Hash;
use bitcoincore_rpc_async::bitcoin::{BlockHash, BlockHeader};
use bitcoincore_rpc_async::json::GetBlockHeaderResult;
use serde_json::value::RawValue;
use tokio::time::Instant;

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
use sol_types::Types::DepositVault;
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client as ReqwestClient, Url};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::marker::PhantomData;

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
            Err(bitcoincore_rpc_async::Error::JsonRpc(
                bitcoincore_rpc_async::jsonrpc::error::Error::Rpc(ref rpcerr),
            )) if rpcerr.code == -32603 => {
                println!("Retrying RPC call due to error: {:?}", rpcerr);
                Err(BackoffError::transient(
                    bitcoincore_rpc_async::Error::JsonRpc(
                        bitcoincore_rpc_async::jsonrpc::error::Error::Rpc(rpcerr.clone()),
                    ),
                ))
            }
            Err(e) => {
                println!("Real RPC error: {:?}", e);
                Err(BackoffError::permanent(e))
            }
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
    ) -> bitcoincore_rpc_async::Result<Vec<T>> {
        let json_rpc_client = self.client.get_jsonrpc_client();

        // First pass: build and store all owned argument vectors.
        let mut v_args_store: Vec<Vec<Box<serde_json::value::RawValue>>> =
            Vec::with_capacity(requests.len());
        for request in requests {
            let v_args: Vec<Box<serde_json::value::RawValue>> = request
                .args
                .iter()
                .map(serde_json::value::to_raw_value)
                .collect::<std::result::Result<_, serde_json::Error>>()?;
            v_args_store.push(v_args);
        }

        // Second pass: build the request data using the stored v_args.
        let mut request_data: Vec<Request<'_>> = Vec::with_capacity(requests.len());
        for (i, request) in requests.iter().enumerate() {
            let args_slice: &[Box<serde_json::value::RawValue>] = v_args_store[i].as_slice();
            let req = json_rpc_client.build_request(request.method, args_slice);
            request_data.push(req);
        }

        // Use our shared retry logic to send the batch
        let responses = retry_rpc_operation(|| async {
            json_rpc_client
                .send_batch(&request_data)
                .await
                .map_err(|e| bitcoincore_rpc_async::Error::JsonRpc(e.into()))
        })
        .await?;

        let mut results = Vec::with_capacity(responses.len());
        for (i, response) in responses.iter().enumerate() {
            let _request = &requests[i];
            let result = response
                .as_ref()
                .ok_or(bitcoincore_rpc_async::Error::JsonRpc(
                    bitcoincore_rpc_async::jsonrpc::error::Error::EmptyBatch,
                ))?
                .result::<T>()
                .map_err(|e| bitcoincore_rpc_async::Error::JsonRpc(e.into()))?;
            results.push(result);
        }
        Ok(results)
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
        retry_rpc_operation(|| async { self.client.call(cmd, args).await }).await
    }
}

pub trait HeaderChainValidator {
    fn validate_header_chain(&self) -> Result<(), RiftSdkError>;
}

impl HeaderChainValidator for Vec<BlockHeader> {
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
    // safely get leaves from a block range
    async fn get_leaves_from_block_range(
        &self,
        start_block_height: u32,
        end_block_height: u32,
        concurrency_limit: Option<usize>,
        expected_parent: Option<[u8; 32]>,
    ) -> crate::errors::Result<Vec<BlockLeaf>>;

    async fn get_headers_from_block_range(
        &self,
        start_block_height: u32,
        end_block_height: u32,
        concurrency_limit: Option<usize>,
        expected_parent: Option<[u8; 32]>,
    ) -> crate::errors::Result<Vec<BlockHeader>>;

    async fn get_chain_tips(&self) -> crate::errors::Result<Vec<ChainTip>>;
    async fn get_block_header_by_height(&self, height: u32) -> crate::errors::Result<BlockHeader>;
}

// TODO: Use RPC batched requests for much faster throughput
#[async_trait::async_trait]
impl BitcoinClientExt for AsyncBitcoinClient {
    async fn get_block_header_by_height(&self, height: u32) -> crate::errors::Result<BlockHeader> {
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

    async fn get_leaves_from_block_range(
        &self,
        start_block_height: u32,
        end_block_height: u32,
        _concurrency_limit: Option<usize>, // no longer used since we use batch requests
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

        let block_hashes: Vec<BlockHash> = self.send_batch(&hash_requests).await.map_err(|e| {
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

        let header_results: Vec<GetBlockHeaderResult> =
            self.send_batch(&header_requests).await.map_err(|e| {
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
            let mut explorer_block_hash: [u8; 32] = block_hash.as_hash().into_inner();
            explorer_block_hash.reverse();

            // Extract chainwork from header (expecting exactly 32 bytes)
            let chainwork: [u8; 32] = header
                .chainwork
                .as_slice()
                .try_into()
                .expect("Chainwork is not 32 bytes");

            let leaf = BlockLeaf::new(explorer_block_hash, height, chainwork);
            // Note: if GetBlockHeaderResult isn't Copy, you may need to clone it.
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
                .as_hash()
                .into_inner();

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
        _concurrency_limit: Option<usize>, // Not used with batch approach
        expected_parent: Option<[u8; 32]>,
    ) -> crate::errors::Result<Vec<BlockHeader>> {
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

        let block_hashes: Vec<BlockHash> = self.send_batch(&hash_requests).await.map_err(|e| {
            RiftSdkError::BitcoinRpcError(format!("Error fetching block hashes: {}", e))
        })?;

        // ===============================
        // Batch #2: getblockheader (verbose=false)
        //
        // This returns the **hex-encoded** serialized block header.
        // We can parse that into `BlockHeader` using Bitcoin's consensus_decode.
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

        let headers: Vec<BlockHeader> = self
            .send_batch(&header_requests)
            .await
            .map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!("Error fetching block headers: {}", e))
            })?
            .iter()
            .map(|header| {
                let bytes: Vec<u8> = FromHex::from_hex(header).unwrap();
                bitcoincore_rpc_async::bitcoin::consensus::encode::deserialize(&bytes)
            })
            .collect::<Result<Vec<BlockHeader>, bitcoincore_rpc_async::bitcoin::consensus::encode::Error>>()
            .map_err(|e| {
                RiftSdkError::BitcoinRpcError(format!("Error deserializing block headers: {}", e))
            })?;

        // ===============================
        // Parse each hex string into a BlockHeader
        // ===============================
        let mut headers_with_height = Vec::with_capacity(num_blocks);
        for (i, header) in headers.into_iter().enumerate() {
            let height = start_block_height + i as u32;

            headers_with_height.push((height, header));
        }

        // Sort by height (just to be sure we're in ascending order)
        headers_with_height.sort_by_key(|(h, _)| *h);

        // Unzip the vector of (height, header) into just the headers
        let headers: Vec<BlockHeader> = headers_with_height
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
            if actual_parent.into_inner() != expected_parent {
                return Err(RiftSdkError::ParentValidationFailed(format!(
                    "Expected parent {} but got {} for the first header",
                    hex::encode(expected_parent),
                    hex::encode(actual_parent.into_inner())
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
