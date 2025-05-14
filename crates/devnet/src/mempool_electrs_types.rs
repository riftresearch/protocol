//! mempoolpc-types – block & address namespace models
//!
//! All structs derive `Serialize` **and** `Deserialize` so they work for
//! both server-side serialization and client-side decoding.

use bitcoin::{BlockHash, Network, Txid};
use serde::{Deserialize, Serialize};

/* --------------------------------------------------------------------- */
/* ---------------------------  /block  -------------------------------- */
/* --------------------------------------------------------------------- */

/// `GET /block/:hash`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockInfo {
    pub id: String,
    pub height: u32,
    pub version: u32,
    pub timestamp: u32,
    pub tx_count: u32,
    pub size: u32,
    pub weight: u32,
    pub merkle_root: String,
    pub previousblockhash: Option<String>,
    pub mediantime: u32,
    // ── Bitcoin-only fields (omitted under `liquid` feature in electrs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub difficulty: Option<f64>,
    // ── Liquid-only extension blob (JSON map)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Value>,
}

/// `GET /block/:hash/status`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockStatus {
    /// `true` if the block is on the best chain.
    pub in_best_chain: bool,
    /// Height on the best chain (absent if orphaned).
    pub height: Option<u32>,
    /// Best-chain hash of the *next* block (absent at the tip).
    pub next_best: Option<BlockHash>,
}

/// `GET /block/:hash/txids`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTxIds(
    /// Ordered txids in the block.
    pub Vec<Txid>,
);

/// `GET /block/:hash/txs` and pagination variants  
/// *Also reused by many address endpoints – see below*
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub txid: Txid,
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<TxInInfo>,
    pub vout: Vec<TxOutInfo>,
    pub size: u32,
    pub weight: u32,
    pub sigops: u32,
    pub fee: u64,
    /// Confirmation data (absent in mempool responses).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<TxStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInInfo {
    pub txid: Txid,
    pub vout: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prevout: Option<TxOutInfo>,
    pub scriptsig: String, // ASM text
    pub scriptsig_asm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Vec<String>>,
    pub is_coinbase: bool,
    pub sequence: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_redeemscript_asm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_witnessscript_asm: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutInfo {
    pub scriptpubkey: String, // hex
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
    // Liquid-only commitments omitted for brevity.
}

/// Mirror of electrs’ `TransactionStatus`
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxStatus {
    pub confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<BlockHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_time: Option<u32>,
}

/* --------------------------------------------------------------------- */
/* -------------------------  /address  -------------------------------- */
/* --------------------------------------------------------------------- */

/// `GET /address/:addr`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressOverview {
    pub address: String,
    pub chain_stats: AddressStats,
    pub mempool_stats: AddressStats,
}

/// Stats object reused for both `chain_stats` and `mempool_stats`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressStats {
    pub funded_txo_count: u64,
    pub funded_txo_sum: u64,
    pub spent_txo_count: u64,
    pub spent_txo_sum: u64,
    pub tx_count: u64,
}

/// `GET /address/:addr/utxo`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressUtxo {
    pub txid: Txid,
    pub vout: u32,
    pub status: TxStatus,
    pub value: u64,
}

/// `GET /address/:addr/txs/*` family –
/// always an array of full `TransactionInfo` objects.
pub type AddressTxs = Vec<TransactionInfo>;

/// `GET /address/:addr/txs/summary`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressSummary {
    /// Most recent confirmed height included in this slice.
    pub last_height: Option<u32>,
    /// Aggregate amounts over the slice.
    pub spent: u64,
    pub received: u64,
    /// The slice of txs (oldest first).
    pub txs: Vec<TransactionInfo>,
}

/* --------------------------------------------------------------------- */
/* -----------------------  helper new-types  -------------------------- */
/* --------------------------------------------------------------------- */

/// `GET /blocks` (paginated)  
/// Electrs returns a simple array; wrap it for type safety.
pub type BlocksPage = Vec<BlockInfo>;

/* --------------------------------------------------------------------- */
/* -----------------------  feature gates  ----------------------------- */
/* --------------------------------------------------------------------- */

/// Compile-time network awareness helper.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTagged<T> {
    pub network: Network,
    pub data: T,
}
