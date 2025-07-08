//! CPFP (Child Pays For Parent) chain analysis for the Bitcoin transaction broadcaster
//!
//! This module analyzes transaction chains to determine the best strategy for fee bumping,
//! whether through RBF on individual transactions or CPFP for chains.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, Txid, Weight};
use tokio::sync::Mutex;
use tokio_rusqlite::Connection;
use tracing::{debug, info};

use crate::btc_txn_broadcaster_db::DbTransaction;

// Transaction overhead: version (4) + marker/flag (2) + input count (1) + output count (1) + locktime (4) = 12 bytes = 42 wu
const TX_OVERHEAD_WEIGHT: u64 = 42;

// - Previous output (txid + vout): 36 bytes (144 wu)
// - Script length: 1 byte (4 wu)
// - Sequence: 4 bytes (16 wu)
// - Witness: 1 + 1 + ~72 + 1 + 33 = ~108 bytes (108 wu)
// Total: 272 wu (68 vbytes)
const P2WPKH_INPUT_WEIGHT: u64 = 272;

// - Amount: 8 bytes (32 wu)
// - Script length: 1 byte (4 wu)
// - Script (OP_0 + 20-byte pubkey hash): 22 bytes (88 wu)
// Total: 124 wu (31 vbytes)
const P2WPKH_OUTPUT_WEIGHT: u64 = 124;

// Maximum allowed fee for CPFP child transaction
const MAX_CPFP_CHILD_FEE_SATS: u64 = 50_000;

// Minimum fee rate ratio to justify CPFP
const MIN_FEE_DEFICIT_RATIO_FOR_CPFP: f64 = 0.9;

// Maximum chain size to prevent memory issues and infinite traversals
const MAX_CHAIN_SIZE: usize = 100;
const MAX_CHAIN_DEPTH: u32 = 25;

/// Configuration for CPFP chain analysis
#[derive(Debug, Clone)]
pub struct CpfpAnalyzerConfig {
    /// Maximum number of transactions in a chain
    pub max_chain_size: usize,
    /// Maximum depth of a transaction chain
    pub max_chain_depth: u32,
    /// Maximum allowed fee for CPFP child transaction
    pub max_cpfp_child_fee_sats: u64,
    /// Minimum fee rate ratio to justify CPFP
    pub min_fee_deficit_ratio: f64,
}

impl Default for CpfpAnalyzerConfig {
    fn default() -> Self {
        Self {
            max_chain_size: MAX_CHAIN_SIZE,
            max_chain_depth: MAX_CHAIN_DEPTH,
            max_cpfp_child_fee_sats: MAX_CPFP_CHILD_FEE_SATS,
            min_fee_deficit_ratio: MIN_FEE_DEFICIT_RATIO_FOR_CPFP,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CpfpChain {
    /// Root transactions that have no parents in the chain
    pub roots: Vec<Txid>,
    /// All transactions in the chain
    pub transactions: HashMap<Txid, ChainTransaction>,
    /// Parent-child relationships
    pub relationships: HashMap<Txid, Vec<Txid>>,
    /// Child-parent relationships for reverse lookup
    pub reverse_relationships: HashMap<Txid, Vec<Txid>>,
    /// Youngest transaction in the chain
    pub youngest_child: Option<Txid>,
    /// Aggregate statistics for the chain
    pub aggregate_stats: ChainStats,
}

#[derive(Debug, Clone)]
pub struct ChainTransaction {
    pub txid: Txid,
    pub fee: Amount,
    pub fee_rate_sat_vb: f64,
    pub weight: Weight,
    pub is_confirmed: bool,
    pub is_rbf_enabled: bool,
    pub broadcasted_at: u64,
    pub depth_in_chain: u32, // 0 for roots, increments for each level
}

#[derive(Debug, Clone)]
pub struct ChainStats {
    pub total_fees: Amount,
    pub total_weight: Weight,
    pub aggregate_fee_rate: f64,
    pub num_transactions: usize,
    pub num_unconfirmed: usize,
    pub oldest_broadcast: u64,
    pub newest_broadcast: u64,
}

/// Analyzes CPFP chains to determine optimal fee bumping strategies
pub struct CpfpChainAnalyzer {
    conn: Arc<Mutex<Connection>>,
    config: CpfpAnalyzerConfig,
}

impl CpfpChainAnalyzer {
    /// Create a new CPFP chain analyzer with default configuration
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            config: CpfpAnalyzerConfig::default(),
        }
    }

    /// Create a new CPFP chain analyzer with custom configuration
    pub fn with_config(conn: Arc<Mutex<Connection>>, config: CpfpAnalyzerConfig) -> Self {
        Self { conn, config }
    }

    /// Analyze all unconfirmed transaction chains
    pub async fn analyze_unconfirmed_chains(&self) -> eyre::Result<Vec<CpfpChain>> {
        let conn = self.conn.lock().await;

        // Get all unconfirmed transactions
        let unconfirmed_txs = self.get_unconfirmed_transactions(&*conn).await?;

        // Get all relationships
        let all_relationships = self.get_all_relationships(&*conn).await?;

        // Build chains from the relationships
        let chains = self.build_chains(unconfirmed_txs, all_relationships)?;

        info!("Analyzed {} CPFP chains", chains.len());
        Ok(chains)
    }

    /// Analyze a specific transaction and its chain
    pub async fn analyze_transaction_chain(&self, txid: Txid) -> eyre::Result<Option<CpfpChain>> {
        let conn = self.conn.lock().await;

        // Get the transaction
        let tx_info = self.get_transaction_info(&*conn, txid).await?;
        if tx_info.is_none() {
            return Ok(None);
        }

        // Get all related transactions so the ancestors and descendants
        let related_txids = self.get_related_transactions(&*conn, txid).await?;

        // Get info for all related transactions
        let mut chain_txs = HashMap::new();
        for related_txid in &related_txids {
            if let Some(tx) = self.get_transaction_info(&*conn, *related_txid).await? {
                chain_txs.insert(*related_txid, tx);
            }
        }

        // Get relationships for these transactions
        let relationships = self
            .get_relationships_for_txids(&*conn, &related_txids)
            .await?;

        // Build the chain
        let chains = self.build_chains(chain_txs, relationships)?;

        // Find the chain containing our target transaction
        Ok(chains
            .into_iter()
            .find(|chain| chain.transactions.contains_key(&txid)))
    }

    /// Get all unconfirmed transactions with their details
    async fn get_unconfirmed_transactions(
        &self,
        conn: &Connection,
    ) -> eyre::Result<HashMap<Txid, DbTransaction>> {
        conn.call(|conn| {
            let mut stmt = conn.prepare(
                "SELECT txid, raw_tx, fee_sats, fee_rate_sat_vb, is_rbf_enabled, 
                        broadcasted_at, weight
                 FROM broadcasted_txs 
                 WHERE is_confirmed = 0 AND replaced_by_txid IS NULL",
            )?;

            let rows = stmt.query_map([], |row| {
                let txid_bytes: Vec<u8> = row.get(0)?;
                let raw_tx: Vec<u8> = row.get(1)?;
                let fee_sats: i64 = row.get(2)?;
                let fee_rate_sat_vb: f64 = row.get(3)?;
                let is_rbf_enabled: i64 = row.get(4)?;
                let broadcasted_at: i64 = row.get(5)?;
                let _weight: i64 = row.get(6)?;

                Ok((
                    txid_bytes,
                    raw_tx,
                    fee_sats,
                    fee_rate_sat_vb,
                    is_rbf_enabled != 0,
                    broadcasted_at,
                    _weight,
                ))
            })?;

            let mut txs = HashMap::new();
            for row in rows {
                let (
                    txid_bytes,
                    raw_tx,
                    fee_sats,
                    fee_rate_sat_vb,
                    is_rbf_enabled,
                    broadcasted_at,
                    _weight,
                ) = row?;

                let txid = Txid::from_slice(&txid_bytes)
                    .map_err(|_| tokio_rusqlite::Error::Other("Invalid txid".into()))?;

                txs.insert(
                    txid,
                    DbTransaction {
                        txid,
                        raw_tx,
                        fee: Amount::from_sat(fee_sats as u64),
                        fee_rate_sat_vb,
                        confirmation_block: None,
                        confirmations: 0,
                        is_rbf_enabled,
                        replaced_by: None,
                        broadcasted_at: broadcasted_at as u64,
                        last_checked: 0,
                    },
                );
            }

            Ok(txs)
        })
        .await
        .map_err(|e| eyre::eyre!("Failed to get unconfirmed transactions: {}", e))
    }

    /// Get all parent-child relationships
    async fn get_all_relationships(&self, conn: &Connection) -> eyre::Result<Vec<(Txid, Txid)>> {
        conn.call(|conn| {
            let mut stmt = conn.prepare("SELECT parent_txid, child_txid FROM tx_relationships")?;

            let rows = stmt.query_map([], |row| {
                let parent_bytes: Vec<u8> = row.get(0)?;
                let child_bytes: Vec<u8> = row.get(1)?;
                Ok((parent_bytes, child_bytes))
            })?;

            let mut relationships = Vec::new();
            for row in rows {
                let (parent_bytes, child_bytes) = row?;

                let parent = Txid::from_slice(&parent_bytes)
                    .map_err(|_| tokio_rusqlite::Error::Other("Invalid parent txid".into()))?;
                let child = Txid::from_slice(&child_bytes)
                    .map_err(|_| tokio_rusqlite::Error::Other("Invalid child txid".into()))?;

                relationships.push((parent, child));
            }

            Ok(relationships)
        })
        .await
        .map_err(|e| eyre::eyre!("Failed to get relationships: {}", e))
    }

    async fn get_transaction_info(
        &self,
        conn: &Connection,
        txid: Txid,
    ) -> eyre::Result<Option<DbTransaction>> {
        let txid_bytes = txid.as_byte_array().to_vec();

        conn.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT raw_tx, fee_sats, fee_rate_sat_vb, is_rbf_enabled, 
                        broadcasted_at, weight, is_confirmed
                 FROM broadcasted_txs 
                 WHERE txid = ?1",
            )?;

            let result = stmt.query_row([txid_bytes.clone()], |row| {
                let raw_tx: Vec<u8> = row.get(0)?;
                let fee_sats: i64 = row.get(1)?;
                let fee_rate_sat_vb: f64 = row.get(2)?;
                let is_rbf_enabled: i64 = row.get(3)?;
                let broadcasted_at: i64 = row.get(4)?;
                let _weight: i64 = row.get(5)?;
                let is_confirmed: i64 = row.get(6)?;

                Ok(DbTransaction {
                    txid,
                    raw_tx,
                    fee: Amount::from_sat(fee_sats as u64),
                    fee_rate_sat_vb,
                    confirmation_block: if is_confirmed != 0 { Some(0) } else { None },
                    confirmations: if is_confirmed != 0 { 1 } else { 0 },
                    is_rbf_enabled: is_rbf_enabled != 0,
                    replaced_by: None,
                    broadcasted_at: broadcasted_at as u64,
                    last_checked: 0,
                })
            });

            match result {
                Ok(tx) => Ok(Some(tx)),
                Err(e) if e.to_string().contains("no rows") => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
        .await
        .map_err(|e| eyre::eyre!("Failed to get transaction info: {}", e))
    }

    async fn get_related_transactions(
        &self,
        conn: &Connection,
        txid: Txid,
    ) -> eyre::Result<HashSet<Txid>> {
        // Use a BFS approach to find all related transactions
        let mut related = HashSet::new();
        let mut to_process = VecDeque::new();
        to_process.push_back(txid);
        related.insert(txid);

        while let Some(current_txid) = to_process.pop_front() {
            if related.len() >= self.config.max_chain_size {
                debug!(
                    "Chain size limit reached ({} transactions), stopping traversal",
                    self.config.max_chain_size
                );
                break;
            }

            let current_bytes = current_txid.as_byte_array().to_vec();

            // Find parents
            let parents: Vec<Txid> = conn
                .call(move |conn| {
                    let mut stmt = conn.prepare(
                        "SELECT parent_txid FROM tx_relationships WHERE child_txid = ?1",
                    )?;

                    let rows = stmt.query_map([current_bytes.clone()], |row| {
                        let parent_bytes: Vec<u8> = row.get(0)?;
                        Ok(parent_bytes)
                    })?;

                    let mut parents = Vec::new();
                    for row in rows {
                        let parent_bytes = row?;
                        let parent = Txid::from_slice(&parent_bytes).map_err(|_| {
                            tokio_rusqlite::Error::Other("Invalid parent txid".into())
                        })?;
                        parents.push(parent);
                    }
                    Ok(parents)
                })
                .await?;

            // Find children
            let current_bytes = current_txid.as_byte_array().to_vec();
            let children: Vec<Txid> = conn
                .call(move |conn| {
                    let mut stmt = conn.prepare(
                        "SELECT child_txid FROM tx_relationships WHERE parent_txid = ?1",
                    )?;

                    let rows = stmt.query_map([current_bytes], |row| {
                        let child_bytes: Vec<u8> = row.get(0)?;
                        Ok(child_bytes)
                    })?;

                    let mut children = Vec::new();
                    for row in rows {
                        let child_bytes = row?;
                        let child = Txid::from_slice(&child_bytes).map_err(|_| {
                            tokio_rusqlite::Error::Other("Invalid child txid".into())
                        })?;
                        children.push(child);
                    }
                    Ok(children)
                })
                .await?;

            // Add new transactions to process
            for parent in parents {
                if related.insert(parent) {
                    to_process.push_back(parent);
                }
            }
            for child in children {
                if related.insert(child) {
                    to_process.push_back(child);
                }
            }
        }

        Ok(related)
    }

    async fn get_relationships_for_txids(
        &self,
        conn: &Connection,
        txids: &HashSet<Txid>,
    ) -> eyre::Result<Vec<(Txid, Txid)>> {
        if txids.is_empty() {
            return Ok(Vec::new());
        }

        // Convert txids to bytes for SQL query
        let txid_bytes: Vec<Vec<u8>> = txids.iter().map(|t| t.as_byte_array().to_vec()).collect();

        // Clone txids for use in the closure
        let txids_clone = txids.clone();

        conn.call(move |conn| {
            let mut relationships = Vec::new();

            for txid_byte in &txid_bytes {
                // Get relationships where this tx is parent
                let mut stmt =
                    conn.prepare("SELECT child_txid FROM tx_relationships WHERE parent_txid = ?1")?;

                let rows = stmt.query_map([txid_byte], |row| {
                    let child_bytes: Vec<u8> = row.get(0)?;
                    Ok(child_bytes)
                })?;

                let parent = Txid::from_slice(txid_byte)
                    .map_err(|_| tokio_rusqlite::Error::Other("Invalid txid".into()))?;

                for row in rows {
                    let child_bytes = row?;
                    let child = Txid::from_slice(&child_bytes)
                        .map_err(|_| tokio_rusqlite::Error::Other("Invalid child txid".into()))?;

                    // Only include if both parent and child are in our set
                    if txids_clone.contains(&child) {
                        relationships.push((parent, child));
                    }
                }
            }

            Ok(relationships)
        })
        .await
        .map_err(|e| eyre::eyre!("Failed to get relationships for txids: {}", e))
    }

    /// Build chains from transactions and relationships
    fn build_chains(
        &self,
        transactions: HashMap<Txid, DbTransaction>,
        relationships: Vec<(Txid, Txid)>,
    ) -> eyre::Result<Vec<CpfpChain>> {
        // Build relationship maps
        let mut parent_to_children: HashMap<Txid, Vec<Txid>> = HashMap::new();
        let mut child_to_parents: HashMap<Txid, Vec<Txid>> = HashMap::new();

        for (parent, child) in &relationships {
            // Only include relationships where both transactions are in our set
            if transactions.contains_key(parent) && transactions.contains_key(child) {
                parent_to_children.entry(*parent).or_default().push(*child);
                child_to_parents.entry(*child).or_default().push(*parent);
            }
        }

        // Find connected components
        let mut visited = HashSet::new();
        let mut chains = Vec::new();

        for txid in transactions.keys() {
            if visited.contains(txid) {
                continue;
            }

            // Build a chain starting from this transaction
            let mut chain_txids = HashSet::new();
            let mut to_visit = VecDeque::new();
            to_visit.push_back(*txid);

            while let Some(current) = to_visit.pop_front() {
                if !chain_txids.insert(current) {
                    continue;
                }
                visited.insert(current);

                // Add parents and children to visit
                if let Some(parents) = child_to_parents.get(&current) {
                    for parent in parents {
                        if transactions.contains_key(parent) {
                            to_visit.push_back(*parent);
                        }
                    }
                }
                if let Some(children) = parent_to_children.get(&current) {
                    for child in children {
                        if transactions.contains_key(child) {
                            to_visit.push_back(*child);
                        }
                    }
                }
            }

            // Build the chain data structure
            let chain = self.build_single_chain(
                chain_txids,
                &transactions,
                &parent_to_children,
                &child_to_parents,
            )?;

            chains.push(chain);
        }

        Ok(chains)
    }

    /// Build a single chain from a set of connected transactions
    fn build_single_chain(
        &self,
        chain_txids: HashSet<Txid>,
        all_transactions: &HashMap<Txid, DbTransaction>,
        parent_to_children: &HashMap<Txid, Vec<Txid>>,
        child_to_parents: &HashMap<Txid, Vec<Txid>>,
    ) -> eyre::Result<CpfpChain> {
        // Find roots
        let mut roots = Vec::new();
        for txid in &chain_txids {
            let has_parent_in_chain = child_to_parents
                .get(txid)
                .map(|parents| parents.iter().any(|p| chain_txids.contains(p)))
                .unwrap_or(false);

            if !has_parent_in_chain {
                roots.push(*txid);
            }
        }

        // Calculate depth for each transaction
        let mut depths = HashMap::new();
        let mut to_process = VecDeque::new();

        for root in &roots {
            depths.insert(*root, 0);
            to_process.push_back((*root, 0));
        }

        while let Some((txid, depth)) = to_process.pop_front() {
            if let Some(children) = parent_to_children.get(&txid) {
                for child in children {
                    if chain_txids.contains(child) && !depths.contains_key(child) {
                        let child_depth = depth + 1;

                        if child_depth > self.config.max_chain_depth {
                            debug!(
                                "Chain depth limit reached ({} levels), skipping deeper transactions",
                                self.config.max_chain_depth
                            );
                            continue;
                        }

                        depths.insert(*child, child_depth);
                        to_process.push_back((*child, child_depth));
                    }
                }
            }
        }

        // Build chain transactions
        let mut chain_transactions: HashMap<Txid, ChainTransaction> = HashMap::new();
        let mut total_fees = Amount::ZERO;
        let mut total_weight = Weight::ZERO;
        let mut num_unconfirmed = 0;
        let mut oldest_broadcast = u64::MAX;
        let mut newest_broadcast = 0;
        let mut youngest_child = None;
        let mut max_depth = 0;

        for txid in &chain_txids {
            let tx_info = all_transactions
                .get(txid)
                .ok_or_else(|| eyre::eyre!("Transaction {} not found", txid))?;

            let depth = depths.get(txid).copied().unwrap_or(0);
            let weight = Weight::from_wu(tx_info.raw_tx.len() as u64 * 4); // Approximate

            let chain_tx = ChainTransaction {
                txid: *txid,
                fee: tx_info.fee,
                fee_rate_sat_vb: tx_info.fee_rate_sat_vb,
                weight,
                is_confirmed: tx_info.confirmations > 0,
                is_rbf_enabled: tx_info.is_rbf_enabled,
                broadcasted_at: tx_info.broadcasted_at,
                depth_in_chain: depth,
            };

            // Update statistics
            total_fees = total_fees + tx_info.fee;
            total_weight = total_weight + weight;
            if tx_info.confirmations == 0 {
                num_unconfirmed += 1;
            }
            oldest_broadcast = oldest_broadcast.min(tx_info.broadcasted_at);
            newest_broadcast = newest_broadcast.max(tx_info.broadcasted_at);

            // Track youngest child, leaf with highest timestamp
            if depth >= max_depth && tx_info.confirmations == 0 {
                if depth > max_depth || youngest_child.is_none() {
                    youngest_child = Some(*txid);
                    max_depth = depth;
                } else if let Some(current_youngest) = youngest_child {
                    if let Some(youngest_tx) = chain_transactions.get(&current_youngest) {
                        if tx_info.broadcasted_at > youngest_tx.broadcasted_at {
                            youngest_child = Some(*txid);
                        }
                    }
                }
            }

            chain_transactions.insert(*txid, chain_tx);
        }

        // Calculate aggregate fee rate
        let aggregate_fee_rate = if total_weight.to_wu() > 0 {
            (total_fees.to_sat() as f64) / (total_weight.to_vbytes_ceil() as f64)
        } else {
            0.0
        };

        // Build final relationships
        let mut chain_relationships = HashMap::new();
        let mut chain_reverse_relationships = HashMap::new();

        for (parent, children) in parent_to_children {
            if chain_txids.contains(parent) {
                let chain_children: Vec<Txid> = children
                    .iter()
                    .filter(|c| chain_txids.contains(*c))
                    .copied()
                    .collect();
                if !chain_children.is_empty() {
                    chain_relationships.insert(*parent, chain_children);
                }
            }
        }

        for (child, parents) in child_to_parents {
            if chain_txids.contains(child) {
                let chain_parents: Vec<Txid> = parents
                    .iter()
                    .filter(|p| chain_txids.contains(*p))
                    .copied()
                    .collect();
                if !chain_parents.is_empty() {
                    chain_reverse_relationships.insert(*child, chain_parents);
                }
            }
        }

        let aggregate_stats = ChainStats {
            total_fees,
            total_weight,
            aggregate_fee_rate,
            num_transactions: chain_transactions.len(),
            num_unconfirmed,
            oldest_broadcast,
            newest_broadcast,
        };

        Ok(CpfpChain {
            roots,
            transactions: chain_transactions,
            relationships: chain_relationships,
            reverse_relationships: chain_reverse_relationships,
            youngest_child,
            aggregate_stats,
        })
    }

    /// Determine if a chain should use CPFP instead of RBF
    pub fn should_use_cpfp(&self, chain: &CpfpChain, target_fee_rate: f64) -> bool {
        if chain.aggregate_stats.num_unconfirmed == 1 {
            if let Some(youngest) = chain.youngest_child {
                if let Some(tx) = chain.transactions.get(&youngest) {
                    if tx.is_rbf_enabled {
                        debug!("Single transaction with RBF enabled, preferring RBF");
                        return false;
                    }
                }
            }
        }

        let fee_deficit_ratio = chain.aggregate_stats.aggregate_fee_rate / target_fee_rate;
        if fee_deficit_ratio > self.config.min_fee_deficit_ratio {
            debug!(
                "Chain fee rate {:.2} is close to target {:.2} (ratio: {:.2}), CPFP not needed",
                chain.aggregate_stats.aggregate_fee_rate, target_fee_rate, fee_deficit_ratio
            );
            return false;
        }

        let weight_estimate = self.estimate_cpfp_weight(chain);
        let required_child_fee = self.calculate_cpfp_fee(chain, target_fee_rate, weight_estimate);

        if required_child_fee > Amount::from_sat(self.config.max_cpfp_child_fee_sats) {
            debug!(
                "CPFP child fee too high: {} sats (max: {}), not recommending CPFP",
                required_child_fee.to_sat(),
                self.config.max_cpfp_child_fee_sats
            );
            return false;
        }

        let all_rbf_enabled = chain
            .transactions
            .values()
            .filter(|tx| !tx.is_confirmed)
            .all(|tx| tx.is_rbf_enabled);

        if all_rbf_enabled && chain.aggregate_stats.num_unconfirmed == 1 {
            debug!("Single RBF-enabled transaction, preferring RBF over CPFP");
            return false;
        }

        debug!(
            "Recommending CPFP for chain with {} txs, aggregate fee rate: {:.2}, target: {:.2}",
            chain.aggregate_stats.num_unconfirmed,
            chain.aggregate_stats.aggregate_fee_rate,
            target_fee_rate
        );

        true
    }

    /// Calculate the fee needed for CPFP to bring chain to target rate
    pub fn calculate_cpfp_fee(
        &self,
        chain: &CpfpChain,
        target_fee_rate: f64,
        child_weight: Weight,
    ) -> Amount {
        let total_weight = chain.aggregate_stats.total_weight + child_weight;
        let target_total_fee =
            (target_fee_rate * total_weight.to_vbytes_ceil() as f64).ceil() as u64;
        let current_total_fee = chain.aggregate_stats.total_fees.to_sat();

        if target_total_fee > current_total_fee {
            Amount::from_sat(target_total_fee - current_total_fee)
        } else {
            Amount::ZERO
        }
    }

    fn estimate_cpfp_weight(&self, chain: &CpfpChain) -> Weight {
        let estimated_inputs = if let Some(youngest_txid) = chain.youngest_child {
            // Check if the youngest transaction already has children
            // If it does, its outputs are already spent, so we can't use them
            let has_children = chain
                .relationships
                .get(&youngest_txid)
                .map(|children| !children.is_empty())
                .unwrap_or(false);

            if has_children {
                // The youngest transaction's outputs are already spent by its children
                // So we gotta find other UTXOs from our wallet to fund the CPFP
                2u64
            } else {
                // The youngest transaction has unspent outputs we can use
                // So we just need 1 of its outputs for the CPFP
                1u64
            }
        } else {
            // No youngest child identified
            // Default to 1 input
            1u64
        };

        let estimated_outputs = if estimated_inputs > 1 {
            // Multiple inputs means combining UTXOs
            // So 2 outputs: 1 for the fee payment, 1 for change
            2u64
        } else {
            // With a single input we can consume it entirely for fees
            // 1 output
            1u64
        };

        let total_weight = TX_OVERHEAD_WEIGHT
            + (estimated_inputs * P2WPKH_INPUT_WEIGHT)
            + (estimated_outputs * P2WPKH_OUTPUT_WEIGHT);

        debug!(
            "Estimated CPFP weight: {} WU ({} vbytes) for chain with youngest: {:?}",
            total_weight,
            total_weight / 4,
            chain.youngest_child
        );

        debug!(
            "CPFP weight breakdown: {} inputs ({} WU), {} outputs ({} WU), overhead ({} WU)",
            estimated_inputs,
            estimated_inputs * P2WPKH_INPUT_WEIGHT,
            estimated_outputs,
            estimated_outputs * P2WPKH_OUTPUT_WEIGHT,
            TX_OVERHEAD_WEIGHT
        );

        Weight::from_wu(total_weight)
    }
}
