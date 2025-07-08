//! RBF (Replace-By-Fee) builder for the Bitcoin transaction broadcaster
//!
//! This module creates replacement transactions
//! for replacing stuck transactions with higher fee versions.

use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::{
    absolute::LockTime, transaction, Amount, FeeRate, OutPoint, Sequence, Transaction, TxIn, TxOut,
    Txid,
};
use tokio::sync::Mutex;
use tokio_rusqlite::Connection;
use tracing::{debug, info, warn};

use crate::btc_txn_broadcaster::{calc_change, BitcoinSigner, InputUtxo};
use crate::btc_txn_broadcaster_db::{mark_tx_replaced, DbTransaction};
use crate::cpfp_analyzer::CpfpChain;
use crate::transaction_monitor::deserialize_transaction;
use crate::utxo_manager::UtxoManager;

const MIN_RELAY_FEE_RATE: u64 = 1;
const MAX_RBF_FEE_MULTIPLIER: f64 = 3.0; // Maximum 3x original fee for safety

#[derive(Debug, Clone)]
pub struct RbfConfig {
    /// Minimum fee rate increase percentage
    pub min_fee_increase_percent: u8,
    /// Minimum absolute fee increase in sats
    pub min_fee_increase_sats: u64,
    /// Minimum relay fee rate in sat/vB
    pub min_relay_fee_rate: u64,
}

impl Default for RbfConfig {
    fn default() -> Self {
        Self {
            min_fee_increase_percent: 10,
            min_fee_increase_sats: 1000,
            min_relay_fee_rate: MIN_RELAY_FEE_RATE,
        }
    }
}

impl RbfConfig {
    pub fn validate(&self) -> eyre::Result<()> {
        if self.min_fee_increase_percent > 100 {
            return Err(eyre::eyre!(
                "Invalid min_fee_increase_percent: {} (must be <= 100)",
                self.min_fee_increase_percent
            ));
        }

        if self.min_relay_fee_rate == 0 {
            return Err(eyre::eyre!("min_relay_fee_rate must be greater than 0"));
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct RbfResult {
    /// The replacement transaction
    pub replacement_tx: Transaction,
    /// The original transaction being replaced
    pub original_txid: Txid,
    /// New fee for the replacement
    pub new_fee: Amount,
    /// New fee rate
    pub new_fee_rate: f64,
    /// UTXOs used as inputs
    pub input_utxos: Vec<InputUtxo>,
}

pub struct RbfBuilder {
    config: RbfConfig,
    utxo_manager: Arc<UtxoManager>,
    db_conn: Arc<Mutex<Connection>>,
}

impl RbfBuilder {
    pub fn new(
        config: RbfConfig,
        utxo_manager: Arc<UtxoManager>,
        db_conn: Arc<Mutex<Connection>>,
    ) -> eyre::Result<Self> {
        config.validate()?;

        Ok(Self {
            config,
            utxo_manager,
            db_conn,
        })
    }

    pub fn with_default_config(
        utxo_manager: Arc<UtxoManager>,
        db_conn: Arc<Mutex<Connection>>,
    ) -> eyre::Result<Self> {
        Self::new(RbfConfig::default(), utxo_manager, db_conn)
    }

    pub async fn build_replacement<S: BitcoinSigner>(
        &self,
        original_tx_data: &DbTransaction,
        target_fee_rate: FeeRate,
        signer: &S,
    ) -> eyre::Result<RbfResult> {
        let original_tx = deserialize_transaction(&original_tx_data.raw_tx)?;

        let min_fee =
            self.calculate_min_rbf_fee(&original_tx, original_tx_data.fee, target_fee_rate)?;

        info!(
            "Building RBF replacement for {}: original fee {} sats -> min new fee {} sats",
            original_tx_data.txid,
            original_tx_data.fee.to_sat(),
            min_fee.to_sat()
        );

        self.build_replacement_with_fee(
            &original_tx,
            original_tx_data.txid,
            min_fee,
            target_fee_rate,
            signer,
        )
        .await
    }

    pub async fn build_chain_replacement<S: BitcoinSigner>(
        &self,
        chain: &CpfpChain,
        target_fee_rate: FeeRate,
        signer: &S,
    ) -> eyre::Result<RbfResult> {
        // Get the youngest child to replace
        let youngest_txid = chain
            .youngest_child
            .ok_or_else(|| eyre::eyre!("Chain has no youngest child"))?;

        let youngest_tx = chain
            .transactions
            .get(&youngest_txid)
            .ok_or_else(|| eyre::eyre!("Youngest child not found in chain"))?;

        if !youngest_tx.is_rbf_enabled {
            return Err(eyre::eyre!("Youngest child does not have RBF enabled"));
        }

        // For chain RBF we needa look at aggregate fee rate
        // The replacement should bump the whole chain to the target rate
        let chain_fee_deficit = self.calculate_chain_fee_deficit(chain, target_fee_rate);

        let raw_tx = self.get_raw_transaction(youngest_txid).await?;
        let original_tx = deserialize_transaction(&raw_tx)?;

        let min_new_fee = youngest_tx.fee + chain_fee_deficit;

        let bip125_min_fee =
            self.calculate_min_rbf_fee(&original_tx, youngest_tx.fee, target_fee_rate)?;

        let final_fee = min_new_fee.max(bip125_min_fee);

        info!(
            "Building chain RBF for {}: original fee {} sats -> new fee {} sats (deficit: {} sats)",
            youngest_txid,
            youngest_tx.fee.to_sat(),
            final_fee.to_sat(),
            chain_fee_deficit.to_sat()
        );

        self.build_replacement_with_fee(
            &original_tx,
            youngest_txid,
            final_fee,
            target_fee_rate,
            signer,
        )
        .await
    }

    async fn get_raw_transaction(&self, txid: Txid) -> eyre::Result<Vec<u8>> {
        let conn = self.db_conn.lock().await;
        let txid_bytes = txid.as_byte_array().to_vec();

        conn.call(move |conn| {
            let mut stmt = conn.prepare("SELECT raw_tx FROM broadcasted_txs WHERE txid = ?1")?;

            let raw_tx: Vec<u8> = stmt
                .query_row([txid_bytes], |row| row.get(0))
                .map_err(|e| {
                    tokio_rusqlite::Error::Other(format!("Transaction not found: {}", e).into())
                })?;

            Ok(raw_tx)
        })
        .await
        .map_err(|e| eyre::eyre!("Failed to get raw transaction: {}", e))
    }

    async fn get_utxo_value(&self, outpoint: OutPoint) -> eyre::Result<Amount> {
        // First, try to get from UTXOs table
        if let Some(amount) = self.get_utxo_value_from_utxos_table(outpoint).await? {
            return Ok(amount);
        }

        // If not found, try to get from broadcasted transactions
        self.get_utxo_value_from_broadcasted_tx(outpoint).await
    }

    async fn get_utxo_value_from_utxos_table(
        &self,
        outpoint: OutPoint,
    ) -> eyre::Result<Option<Amount>> {
        let conn = self.db_conn.lock().await;
        let txid_bytes = outpoint.txid.as_byte_array().to_vec();
        let vout = outpoint.vout;

        conn.call(move |conn| {
            let mut stmt =
                conn.prepare("SELECT value_sats FROM utxos WHERE txid = ?1 AND vout = ?2")?;

            match stmt.query_row((txid_bytes, vout as i64), |row| {
                let value_sats: i64 = row.get(0)?;
                Ok(Amount::from_sat(value_sats as u64))
            }) {
                Ok(amount) => Ok(Some(amount)),
                Err(e) if e.to_string().contains("no rows") => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
        .await
        .map_err(|e| eyre::eyre!("Database error while fetching UTXO from utxos table: {}", e))
    }

    async fn get_utxo_value_from_broadcasted_tx(&self, outpoint: OutPoint) -> eyre::Result<Amount> {
        let conn = self.db_conn.lock().await;
        let txid_bytes = outpoint.txid.as_byte_array().to_vec();

        let raw_tx = conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT raw_tx FROM broadcasted_txs WHERE txid = ?1")?;

                match stmt.query_row([txid_bytes], |row| {
                    let raw_tx: Vec<u8> = row.get(0)?;
                    Ok(raw_tx)
                }) {
                    Ok(raw_tx) => Ok(Some(raw_tx)),
                    Err(e) if e.to_string().contains("no rows") => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
            .map_err(|e| eyre::eyre!("Database error while fetching transaction: {}", e))?;

        match raw_tx {
            Some(raw_tx) => {
                let tx = deserialize_transaction(&raw_tx)?;
                if outpoint.vout as usize >= tx.output.len() {
                    return Err(eyre::eyre!(
                        "Invalid output index {} for transaction {} (tx has {} outputs)",
                        outpoint.vout,
                        outpoint.txid,
                        tx.output.len()
                    ));
                }
                Ok(tx.output[outpoint.vout as usize].value)
            }
            None => Err(eyre::eyre!(
                "UTXO value not found for outpoint {} (not in utxos or broadcasted_txs tables)",
                outpoint
            )),
        }
    }

    fn calculate_min_rbf_fee(
        &self,
        original_tx: &Transaction,
        original_fee: Amount,
        target_fee_rate: FeeRate,
    ) -> eyre::Result<Amount> {
        let tx_weight = original_tx.weight();

        // Pay for bandwidth at minimum relay fee rate
        let bandwidth_fee = FeeRate::from_sat_per_vb(self.config.min_relay_fee_rate)
            .ok_or_else(|| eyre::eyre!("Invalid relay fee rate"))?
            .fee_wu(tx_weight)
            .ok_or_else(|| eyre::eyre!("Fee calculation overflow"))?;

        // Pay original fee + bandwidth fee
        let bip125_min = original_fee + bandwidth_fee;

        // Ensure minimum percentage increase from original fee
        let percent_increase =
            (original_fee.to_sat() as f64 * self.config.min_fee_increase_percent as f64 / 100.0)
                .ceil() as u64;
        let config_min = original_fee
            + Amount::from_sat(percent_increase.max(self.config.min_fee_increase_sats));

        // Target fee based on desired rate
        let target_fee = target_fee_rate
            .fee_wu(tx_weight)
            .ok_or_else(|| eyre::eyre!("Target fee calculation overflow"))?;

        // Take the maximum of all requirements
        let min_fee = bip125_min.max(config_min).max(target_fee);

        // Apply maximum fee protection
        let max_allowed_fee =
            Amount::from_sat((original_fee.to_sat() as f64 * MAX_RBF_FEE_MULTIPLIER) as u64);
        if min_fee > max_allowed_fee {
            warn!(
                "RBF fee {} sats exceeds maximum allowed {} sats ({}x original)",
                min_fee.to_sat(),
                max_allowed_fee.to_sat(),
                MAX_RBF_FEE_MULTIPLIER
            );
            return Err(eyre::eyre!(
                "RBF fee would exceed maximum allowed ({}x original fee)",
                MAX_RBF_FEE_MULTIPLIER
            ));
        }

        debug!(
            "RBF fee calculation: BIP-125 min={}, config min={}, target={}, final={}",
            bip125_min.to_sat(),
            config_min.to_sat(),
            target_fee.to_sat(),
            min_fee.to_sat()
        );

        Ok(min_fee)
    }

    /// Build a replacement transaction with a specific fee
    async fn build_replacement_with_fee<S: BitcoinSigner>(
        &self,
        original_tx: &Transaction,
        original_txid: Txid,
        target_fee: Amount,
        target_fee_rate: FeeRate,
        signer: &S,
    ) -> eyre::Result<RbfResult> {
        // Get the outputs from the original transaction
        let mut outputs = Vec::new();
        let change_script = signer.get_script_pubkey();

        // Identify and preserve non-change outputs
        for output in &original_tx.output {
            if output.script_pubkey != change_script {
                outputs.push(output.clone());
            }
        }

        let payment_amount: Amount = outputs.iter().map(|o| o.value).sum();

        // Get original input values
        let mut original_input_value = Amount::ZERO;
        let mut original_utxos = Vec::new();

        for input in &original_tx.input {
            let value = self.get_utxo_value(input.previous_output).await?;
            original_input_value = original_input_value + value;
            original_utxos.push(InputUtxo::new(input.previous_output, value));
        }

        // Check if original inputs are sufficient
        let required_amount = payment_amount + target_fee;

        let (input_utxos, _change_amount) = if original_input_value >= required_amount {
            // Original inputs are sufficient
            let change_val = original_input_value - required_amount;
            (original_utxos, Some(change_val))
        } else {
            // Need additional inputs
            let additional_needed = required_amount - original_input_value;

            info!(
                "RBF needs {} additional sats - selecting more UTXOs",
                additional_needed.to_sat()
            );

            // Select additional UTXOs
            let (additional_utxos, additional_change) = self
                .utxo_manager
                .select_and_lock_utxos(
                    additional_needed,
                    target_fee_rate,
                    FeeRate::from_sat_per_vb(1).unwrap(),
                )
                .await?;

            // Combine original and additional UTXOs
            let mut all_utxos = original_utxos;
            all_utxos.extend(additional_utxos);

            // Calculate final change
            let total_input: Amount = all_utxos.iter().map(|u| u.value).sum();
            let change_val = total_input - required_amount;

            (all_utxos, additional_change.or(Some(change_val)))
        };

        // Calculate if we need a change output
        let utxo_refs: Vec<&InputUtxo> = input_utxos.iter().collect();
        let final_change = calc_change(&utxo_refs, payment_amount, target_fee_rate)?;

        // Add change output if needed
        if let Some(change_amt) = final_change {
            outputs.push(TxOut {
                value: change_amt,
                script_pubkey: change_script,
            });
        }

        // Build the replacement transaction
        let mut inputs = Vec::new();
        for utxo in &input_utxos {
            inputs.push(TxIn {
                previous_output: utxo.outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence(0xFFFFFFFD), // Signal RBF
                witness: bitcoin::Witness::new(),
            });
        }

        let unsigned_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        // Validate transaction size
        let estimated_weight = unsigned_tx.weight();
        if estimated_weight.to_wu() > 400_000 {
            return Err(eyre::eyre!(
                "Transaction too large: {} weight units (max: 400,000)",
                estimated_weight.to_wu()
            ));
        }

        // Sign the transaction
        let signed_tx = signer.sign_transaction(&unsigned_tx, &input_utxos)?;

        // Calculate actual fee
        let total_input: Amount = input_utxos.iter().map(|u| u.value).sum();
        let total_output: Amount = signed_tx.output.iter().map(|o| o.value).sum();
        let actual_fee = total_input - total_output;
        let actual_fee_rate =
            (actual_fee.to_sat() as f64) / (signed_tx.weight().to_vbytes_ceil() as f64);

        info!(
            "Built RBF replacement: {} -> {}, fee {} sats ({:.2} sat/vB)",
            original_txid,
            signed_tx.compute_txid(),
            actual_fee.to_sat(),
            actual_fee_rate
        );

        Ok(RbfResult {
            replacement_tx: signed_tx,
            original_txid,
            new_fee: actual_fee,
            new_fee_rate: actual_fee_rate,
            input_utxos,
        })
    }

    /// Calculate how much additional fee is needed to bring a chain to target rate
    fn calculate_chain_fee_deficit(&self, chain: &CpfpChain, target_fee_rate: FeeRate) -> Amount {
        let target_total_fee = (target_fee_rate.to_sat_per_vb_ceil() as f64
            * chain.aggregate_stats.total_weight.to_vbytes_ceil() as f64)
            .ceil() as u64;

        let current_total_fee = chain.aggregate_stats.total_fees.to_sat();

        if target_total_fee > current_total_fee {
            Amount::from_sat(target_total_fee - current_total_fee)
        } else {
            Amount::ZERO
        }
    }

    pub async fn update_database_after_rbf(
        &self,
        original_txid: Txid,
        replacement_txid: Txid,
    ) -> eyre::Result<()> {
        let conn = self.db_conn.lock().await;
        mark_tx_replaced(&*conn, original_txid, replacement_txid).await?;
        info!(
            "Updated database: {} replaced by {}",
            original_txid, replacement_txid
        );
        Ok(())
    }
}
