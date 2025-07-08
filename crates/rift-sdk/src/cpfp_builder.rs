//! CPFP (Child Pays For Parent) builder for the Bitcoin transaction broadcaster
//!
//! This module creates child transactions that pay higher fees to incentivize
//! miners to confirm both the parent and child transactions together.

use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::{
    absolute::LockTime, transaction, Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid,
};
use tokio::sync::Mutex;
use tokio_rusqlite::{params, Connection};
use tracing::{debug, info};

use crate::btc_txn_broadcaster::{BitcoinSigner, InputUtxo, CHANGE_OUTPUT_W, CHANGE_SPEND_W};
use crate::btc_txn_broadcaster_db::{add_tx_relationships, DbTransaction};
use crate::cpfp_analyzer::CpfpChain;
use crate::transaction_monitor::deserialize_transaction;
use crate::utxo_manager::UtxoManager;

#[derive(Debug, Clone)]
pub struct CpfpConfig {
    /// Minimum output value for CPFP
    pub min_output_value: u64,
    /// Maximum allowed fee multiplier
    pub max_fee_multiplier: f64,
}

impl Default for CpfpConfig {
    fn default() -> Self {
        Self {
            min_output_value: 546,
            max_fee_multiplier: 2.0,
        }
    }
}

#[derive(Debug)]
pub struct CpfpResult {
    /// The child transaction
    pub child_tx: Transaction,
    /// Parent transactions being accelerated
    pub parent_txids: Vec<Txid>,
    /// Fee paid by the child
    pub child_fee: Amount,
    /// Effective fee rate for the entire package
    pub package_fee_rate: f64,
    /// UTXOs used as inputs
    pub input_utxos: Vec<InputUtxo>,
}

pub struct CpfpBuilder {
    config: CpfpConfig,
    utxo_manager: Arc<UtxoManager>,
    db_conn: Arc<Mutex<Connection>>,
}

impl CpfpBuilder {
    pub fn new(
        config: CpfpConfig,
        utxo_manager: Arc<UtxoManager>,
        db_conn: Arc<Mutex<Connection>>,
    ) -> Self {
        Self {
            config,
            utxo_manager,
            db_conn,
        }
    }

    fn create_single_tx_chain(tx_data: &DbTransaction, weight: bitcoin::Weight) -> CpfpChain {
        CpfpChain {
            roots: vec![tx_data.txid],
            transactions: [(
                tx_data.txid,
                crate::cpfp_analyzer::ChainTransaction {
                    txid: tx_data.txid,
                    fee: tx_data.fee,
                    fee_rate_sat_vb: tx_data.fee_rate_sat_vb,
                    weight,
                    is_confirmed: false,
                    is_rbf_enabled: tx_data.is_rbf_enabled,
                    broadcasted_at: tx_data.broadcasted_at,
                    depth_in_chain: 0,
                },
            )]
            .into_iter()
            .collect(),
            relationships: Default::default(),
            reverse_relationships: Default::default(),
            youngest_child: Some(tx_data.txid),
            aggregate_stats: crate::cpfp_analyzer::ChainStats {
                total_fees: tx_data.fee,
                total_weight: weight,
                aggregate_fee_rate: tx_data.fee_rate_sat_vb,
                num_transactions: 1,
                num_unconfirmed: 1,
                oldest_broadcast: tx_data.broadcasted_at,
                newest_broadcast: tx_data.broadcasted_at,
            },
        }
    }

    pub async fn build_cpfp_for_chain<S: BitcoinSigner>(
        &self,
        chain: &CpfpChain,
        target_fee_rate: FeeRate,
        required_child_fee: Amount,
        signer: &S,
    ) -> eyre::Result<CpfpResult> {
        let youngest_txid = chain
            .youngest_child
            .ok_or_else(|| eyre::eyre!("Chain has no youngest child"))?;

        let youngest_tx_data = self.get_transaction_data(youngest_txid).await?;
        let youngest_tx = deserialize_transaction(&youngest_tx_data.raw_tx)?;

        // Find spendable outputs from the youngest transaction
        let spendable_outputs =
            self.find_spendable_outputs(&youngest_tx, youngest_txid, signer.get_script_pubkey())?;

        if spendable_outputs.is_empty() {
            return Err(eyre::eyre!(
                "No spendable outputs found in youngest transaction"
            ));
        }

        // Validate that outputs are unspent
        self.validate_outputs_unspent(&spendable_outputs).await?;

        info!(
            "Building CPFP for chain with {} transactions, spending {} outputs from {}",
            chain.aggregate_stats.num_transactions,
            spendable_outputs.len(),
            youngest_txid
        );

        // Build the child transaction
        self.build_child_transaction(
            spendable_outputs,
            required_child_fee,
            target_fee_rate,
            chain,
            signer,
        )
        .await
    }

    pub async fn build_cpfp_for_single<S: BitcoinSigner>(
        &self,
        parent_tx_data: &DbTransaction,
        target_fee_rate: FeeRate,
        signer: &S,
    ) -> eyre::Result<CpfpResult> {
        let parent_tx = deserialize_transaction(&parent_tx_data.raw_tx)?;

        // Find spendable outputs from the parent
        let spendable_outputs = self.find_spendable_outputs(
            &parent_tx,
            parent_tx_data.txid,
            signer.get_script_pubkey(),
        )?;

        if spendable_outputs.is_empty() {
            return Err(eyre::eyre!(
                "No spendable outputs found in parent transaction"
            ));
        }

        // Validate that outputs are unspent
        self.validate_outputs_unspent(&spendable_outputs).await?;

        // Calculate required child fee
        let parent_weight = parent_tx.weight();
        let estimated_child_weight = bitcoin::Weight::from_wu(
            (spendable_outputs.len() as u64 * CHANGE_SPEND_W.to_wu())
                + CHANGE_OUTPUT_W.to_wu()
                + 40, // overhead
        );

        let total_weight = parent_weight + estimated_child_weight;
        let target_total_fee = target_fee_rate
            .fee_wu(total_weight)
            .ok_or_else(|| eyre::eyre!("Fee calculation overflow"))?;

        let required_child_fee = if target_total_fee > parent_tx_data.fee {
            target_total_fee - parent_tx_data.fee
        } else {
            Amount::ZERO
        };

        info!(
            "Building CPFP for single transaction {}: parent fee {} sats, child fee {} sats",
            parent_tx_data.txid,
            parent_tx_data.fee.to_sat(),
            required_child_fee.to_sat()
        );

        let chain = Self::create_single_tx_chain(parent_tx_data, parent_weight);

        self.build_child_transaction(
            spendable_outputs,
            required_child_fee,
            target_fee_rate,
            &chain,
            signer,
        )
        .await
    }

    async fn validate_outputs_unspent(&self, outputs: &[InputUtxo]) -> eyre::Result<()> {
        let conn = self.db_conn.lock().await;

        for utxo in outputs {
            let txid_bytes = utxo.outpoint.txid.as_byte_array().to_vec();
            let vout = utxo.outpoint.vout as i64;

            let is_spent = conn
                .call(move |conn| {
                    let mut stmt =
                        conn.prepare("SELECT is_spent FROM utxos WHERE txid = ?1 AND vout = ?2")?;

                    match stmt.query_row(params![txid_bytes, vout], |row| {
                        let is_spent: i64 = row.get(0)?;
                        Ok(is_spent != 0)
                    }) {
                        Ok(spent) => Ok(Some(spent)),
                        Err(e) if e.to_string().contains("no rows") => Ok(None),
                        Err(e) => Err(e.into()),
                    }
                })
                .await?;

            match is_spent {
                Some(true) => {
                    return Err(eyre::eyre!(
                        "Output {}:{} is already spent",
                        utxo.outpoint.txid,
                        utxo.outpoint.vout
                    ));
                }
                None => {
                    debug!(
                        "Output {}:{} not found in UTXO database (from unconfirmed parent)",
                        utxo.outpoint.txid, utxo.outpoint.vout
                    );
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn find_spendable_outputs(
        &self,
        tx: &Transaction,
        txid: Txid,
        wallet_script: ScriptBuf,
    ) -> eyre::Result<Vec<InputUtxo>> {
        let mut spendable = Vec::new();

        for (vout, output) in tx.output.iter().enumerate() {
            // Check if this output belongs to our wallet
            if output.script_pubkey == wallet_script
                && output.value >= Amount::from_sat(self.config.min_output_value)
            {
                let outpoint = OutPoint::new(txid, vout as u32);
                spendable.push(InputUtxo::new(outpoint, output.value));
            }
        }

        spendable.sort_by(|a, b| b.value.cmp(&a.value));

        debug!(
            "Found {} spendable outputs in transaction {}, total value: {} sats",
            spendable.len(),
            txid,
            spendable.iter().map(|u| u.value.to_sat()).sum::<u64>()
        );

        Ok(spendable)
    }

    async fn build_child_transaction<S: BitcoinSigner>(
        &self,
        parent_outputs: Vec<InputUtxo>,
        required_child_fee: Amount,
        target_fee_rate: FeeRate,
        chain: &CpfpChain,
        signer: &S,
    ) -> eyre::Result<CpfpResult> {
        let total_input: Amount = parent_outputs.iter().map(|u| u.value).sum();

        if total_input <= required_child_fee {
            let additional_needed =
                required_child_fee - total_input + Amount::from_sat(self.config.min_output_value);

            info!(
                "Parent outputs insufficient for CPFP fee. Need {} additional sats",
                additional_needed.to_sat()
            );

            // If transaction broadcast fails, these UTXOs will remain locked.
            let (additional_utxos, _) = self
                .utxo_manager
                .select_and_lock_utxos(
                    additional_needed,
                    target_fee_rate,
                    FeeRate::from_sat_per_vb(1).unwrap(),
                )
                .await
                .map_err(|e| eyre::eyre!("Failed to select additional UTXOs: {}", e))?;

            let mut all_inputs = parent_outputs;
            all_inputs.extend(additional_utxos);

            self.build_transaction_with_inputs(all_inputs, required_child_fee, chain, signer)
                .await
        } else {
            // Parent outputs are sufficient
            self.build_transaction_with_inputs(parent_outputs, required_child_fee, chain, signer)
                .await
        }
    }

    async fn build_transaction_with_inputs<S: BitcoinSigner>(
        &self,
        input_utxos: Vec<InputUtxo>,
        target_fee: Amount,
        chain: &CpfpChain,
        signer: &S,
    ) -> eyre::Result<CpfpResult> {
        let total_input: Amount = input_utxos.iter().map(|u| u.value).sum();

        // Use configurable fee multiplier
        let max_allowed_fee =
            Amount::from_sat((total_input.to_sat() as f64 * self.config.max_fee_multiplier) as u64);

        if target_fee > max_allowed_fee {
            return Err(eyre::eyre!(
                "CPFP fee {} sats exceeds maximum allowed fee {} sats ({}x input value)",
                target_fee.to_sat(),
                max_allowed_fee.to_sat(),
                self.config.max_fee_multiplier
            ));
        }

        let output_amount = total_input
            .checked_sub(target_fee)
            .ok_or_else(|| eyre::eyre!("Insufficient funds for CPFP fee"))?;

        let outputs = if output_amount >= Amount::from_sat(self.config.min_output_value) {
            vec![TxOut {
                value: output_amount,
                script_pubkey: signer.get_script_pubkey(),
            }]
        } else {
            info!(
                "CPFP output would be dust ({} sats), creating tx with no outputs (all to fees)",
                output_amount.to_sat()
            );
            vec![]
        };

        let mut inputs = Vec::new();
        for utxo in &input_utxos {
            inputs.push(TxIn {
                previous_output: utxo.outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence(0xFFFFFFFE), // Not signaling RBF (we want immediate confirmation)
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
        let tx_weight = unsigned_tx.weight();
        if tx_weight.to_wu() > 400_000 {
            return Err(eyre::eyre!(
                "Transaction too large: {} weight units (max: 400,000)",
                tx_weight.to_wu()
            ));
        }

        let signed_tx = signer.sign_transaction(&unsigned_tx, &input_utxos)?;
        let child_txid = signed_tx.compute_txid();

        let total_output: Amount = signed_tx.output.iter().map(|o| o.value).sum();
        let actual_fee = total_input - total_output;

        let total_package_fee = chain.aggregate_stats.total_fees + actual_fee;
        let total_package_weight = chain.aggregate_stats.total_weight + signed_tx.weight();
        let package_fee_rate =
            (total_package_fee.to_sat() as f64) / (total_package_weight.to_vbytes_ceil() as f64);

        // Only collect parent txids from the chain, not from all inputs
        let parent_txids: Vec<Txid> = chain.transactions.keys().cloned().collect();

        info!(
            "Built CPFP child {}: fee {} sats, package rate {:.2} sat/vB",
            child_txid,
            actual_fee.to_sat(),
            package_fee_rate
        );

        Ok(CpfpResult {
            child_tx: signed_tx,
            parent_txids,
            child_fee: actual_fee,
            package_fee_rate,
            input_utxos,
        })
    }

    async fn get_transaction_data(&self, txid: Txid) -> eyre::Result<DbTransaction> {
        let conn = self.db_conn.lock().await;
        let txid_bytes = txid.as_byte_array().to_vec();

        conn.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT raw_tx, fee_sats, fee_rate_sat_vb, is_rbf_enabled, 
                        broadcasted_at, confirmations
                 FROM broadcasted_txs 
                 WHERE txid = ?1",
            )?;

            let result = stmt.query_row([txid_bytes], |row| {
                let raw_tx: Vec<u8> = row.get(0)?;
                let fee_sats: i64 = row.get(1)?;
                let fee_rate_sat_vb: f64 = row.get(2)?;
                let is_rbf_enabled: i64 = row.get(3)?;
                let broadcasted_at: i64 = row.get(4)?;
                let confirmations: i64 = row.get(5)?;

                Ok(DbTransaction {
                    txid,
                    raw_tx,
                    fee: Amount::from_sat(fee_sats as u64),
                    fee_rate_sat_vb,
                    confirmation_block: if confirmations > 0 { Some(0) } else { None },
                    confirmations,
                    is_rbf_enabled: is_rbf_enabled != 0,
                    replaced_by: None,
                    broadcasted_at: broadcasted_at as u64,
                    last_checked: 0,
                })
            });

            match result {
                Ok(tx) => Ok(tx),
                Err(e) => Err(tokio_rusqlite::Error::Other(
                    format!("Transaction not found: {}", e).into(),
                )),
            }
        })
        .await
        .map_err(|e| eyre::eyre!("Failed to get transaction data: {}", e))
    }

    pub async fn update_database_after_cpfp(
        &self,
        child_txid: Txid,
        parent_txids: &[Txid],
    ) -> eyre::Result<()> {
        let conn = self.db_conn.lock().await;

        // Add parent-child relationships
        let relationships: Vec<(Txid, Txid, usize)> = parent_txids
            .iter()
            .enumerate()
            .map(|(idx, &parent_txid)| (parent_txid, child_txid, idx))
            .collect();

        add_tx_relationships(&*conn, &relationships).await?;

        info!(
            "Updated database: CPFP child {} accelerates {} parent(s)",
            child_txid,
            parent_txids.len()
        );

        Ok(())
    }
}
