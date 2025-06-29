//! Simple async broadcaster that selects coins, computes the exact fee and
//! (optionally) adds a change output – all in one place.
//
//  * Assumes the wallet uses P2WPKH for both its receive and change outputs.
//  * Depends on the bitcoin_coin_selection crate for input selection but
//    computes the change output (value **and** decision to include it) here.

use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::{
    absolute::LockTime, address::NetworkChecked, transaction, Amount, FeeRate, OutPoint,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Weight, Witness,
};
use bitcoin_coin_selection::{self as cs, WeightedUtxo};
use bitcoincore_rpc_async::RpcApi;
use esplora_client::AsyncClient as EsploraClient;
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        oneshot,
    },
    task::JoinSet,
};
use tracing::info;

use crate::bitcoin_utils::AsyncBitcoinClient;

/// TODO: Make these fields within the Signer trait instead of enshrining P2WPKH
/// Weight constants for P2WPKH (see BIP‑141)
const CHANGE_OUTPUT_W: Weight = Weight::from_vb_unchecked(31); // P2WPKH output
const CHANGE_SPEND_W: Weight = Weight::from_vb_unchecked(68); // spending it later
const TX_BASE_W: Weight = Weight::from_vb_unchecked(10);

/// Helper: given the selected inputs and the intended pay‑to outputs, decide
/// whether a change output is needed and – if so – return its value.
fn calc_change<U: WeightedUtxo>(
    inputs: &[&U],
    pay_value: Amount, // sum of *recipient* outputs
    fee_rate: FeeRate,
) -> eyre::Result<Option<Amount>> {
    // 1. Sum values/weights of the chosen inputs
    let (inp_val, inp_w) = inputs
        .iter()
        .try_fold((Amount::ZERO, Weight::ZERO), |acc, u| {
            Some((
                acc.0 + u.value(),
                acc.1.checked_add(u.satisfaction_weight())?,
            ))
        })
        .ok_or_else(|| eyre::eyre!("weight overflow"))?;

    // 2. Weight of the pay‑to outputs (all assumed P2WPKH for now)
    let outs_w = Weight::from_vb(31 * (pay_value != Amount::ZERO) as u64 * inputs.len() as u64) // 31 vB per output
        .unwrap_or(Weight::ZERO);

    // 3. Fee without change
    let w_no_change = TX_BASE_W + inp_w + outs_w;
    let fee_no_change = fee_rate
        .fee_wu(w_no_change)
        .ok_or_else(|| eyre::eyre!("fee overflow"))?;

    let remainder = inp_val
        .checked_sub(pay_value + fee_no_change)
        .ok_or_else(|| eyre::eyre!("inputs do not cover payment"))?;

    // Core's MIN_CHANGE constant
    const CHANGE_LOWER: Amount = Amount::from_sat(50_000);

    if remainder < CHANGE_LOWER {
        return Ok(None); // "tip" the miner, no change
    }

    // 4. Fee with change output
    let w_with_change = w_no_change + CHANGE_OUTPUT_W;
    let fee_with_change = fee_rate
        .fee_wu(w_with_change)
        .ok_or_else(|| eyre::eyre!("fee overflow"))?;

    let change_val = inp_val
        .checked_sub(pay_value + fee_with_change)
        .ok_or_else(|| eyre::eyre!("inputs do not cover payment + fee"))?;

    if change_val < CHANGE_LOWER {
        Ok(None)
    } else {
        Ok(Some(change_val))
    }
}

/// A trait for signing transactions from a Bitcoin wallet.
pub trait BitcoinSigner {
    fn sign_transaction(
        &self,
        tx: &Transaction,
        utxo_inputs: &[InputUtxo],
    ) -> eyre::Result<Transaction>;
    fn get_script_pubkey(&self) -> ScriptBuf; // script for change output
    fn get_address(&self) -> bitcoin::Address<NetworkChecked>;
}

#[async_trait]
pub trait BitcoinTransactionBroadcasterTrait {
    async fn new<S: BitcoinSigner + Send + Sync + 'static>(
        btc_rpc: Arc<AsyncBitcoinClient>,
        esplora_client: Arc<EsploraClient>,
        btc_signer: S,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Self;

    async fn broadcast_transaction(&self, tx_outs: &[TxOut]) -> eyre::Result<Txid>;
    async fn can_fund_transaction(&self, tx: &[TxOut]) -> eyre::Result<bool>;
}

#[derive(Debug)]
struct Request {
    tx_outs: Vec<TxOut>,
    response_tx: oneshot::Sender<eyre::Result<Txid>>,
}

pub struct SimpleBitcoinTransactionBroadcaster {
    request_sender: Sender<Request>,
}

#[async_trait]
impl BitcoinTransactionBroadcasterTrait for SimpleBitcoinTransactionBroadcaster {
    async fn new<S: BitcoinSigner + Send + Sync + 'static>(
        btc_rpc: Arc<AsyncBitcoinClient>,
        esplora_client: Arc<EsploraClient>,
        btc_signer: S,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Self {
        let (request_sender, request_receiver) = channel(128);

        join_set.spawn(async move {
            consume_broadcast_queue(btc_rpc, esplora_client, btc_signer, request_receiver).await
        });

        Self { request_sender }
    }

    async fn broadcast_transaction(&self, tx_outs: &[TxOut]) -> eyre::Result<Txid> {
        let (response_tx, rx) = oneshot::channel();
        self.request_sender
            .send(Request {
                tx_outs: tx_outs.to_vec(),
                response_tx,
            })
            .await
            .map_err(|_| eyre::eyre!("queue error"))?;
        rx.await?
    }

    async fn can_fund_transaction(&self, _tx: &[TxOut]) -> eyre::Result<bool> {
        Ok(true) // TODO
    }
}

// Lightweight UTXO wrapper implementing WeightedUtxo
#[derive(Debug, Clone)]
pub struct InputUtxo {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub weight: Weight,
}

impl WeightedUtxo for InputUtxo {
    fn satisfaction_weight(&self) -> Weight {
        self.weight
    }
    fn value(&self) -> Amount {
        self.value
    }
}

impl InputUtxo {
    fn new(outpoint: OutPoint, value: Amount) -> Self {
        Self {
            outpoint,
            value,
            weight: CHANGE_SPEND_W,
        }
    }
}

async fn consume_broadcast_queue<S: BitcoinSigner + Send + Sync + 'static>(
    btc_rpc: Arc<AsyncBitcoinClient>,
    esplora: Arc<EsploraClient>,
    signer: S,
    mut rx: Receiver<Request>,
) -> eyre::Result<()> {
    let addr = signer.get_address();
    let long_term_fee_rate = FeeRate::from_sat_per_vb(1).unwrap();

    while let Some(req) = rx.recv().await {
        let pay_outs = req.tx_outs.clone();
        let pay_value: Amount = pay_outs.iter().map(|o| o.value).sum();
        info!("New request: {:#?}", req);

        // TODO: Use our oracle instead:
        // --- fee estimation ---
        let fee_rate_sat_vb = FeeRate::from_sat_per_vb(
            esplora
                .get_fee_estimates()
                .await?
                .get(&1)
                .copied()
                .unwrap_or(2.0) // fall‑back - increased to be more conservative
                .ceil() as u64,
        )
        .expect("from sat per vb overflow");

        // --- gather UTXOs & run coin‑selection ---
        let utxos_remote = esplora.get_address_utxo(&addr).await?;
        let utxo_wrapped: Vec<InputUtxo> = utxos_remote
            .iter()
            .map(|u| InputUtxo::new(OutPoint::new(u.txid, u.vout), Amount::from_sat(u.value)))
            .collect();

        info!("UTXOs: {:#?}", utxo_wrapped);

        let selected_input_utxos = cs::select_coins(
            pay_value,
            bitcoin::transaction::effective_value(
                fee_rate_sat_vb,
                CHANGE_OUTPUT_W,
                Amount::from_sat(50_000),
            )
            .unwrap_or(Amount::from_sat(1000).to_signed().unwrap())
            .to_unsigned()
            .unwrap_or(Amount::from_sat(1000)), // fallback cost_of_change
            fee_rate_sat_vb,
            long_term_fee_rate,
            &utxo_wrapped,
        );
        if selected_input_utxos.is_none() {
            let _ = req.response_tx.send(Err(eyre::eyre!("insufficient funds")));
            continue;
        }
        let (_, selected_input_utxos) = selected_input_utxos.unwrap();

        // --- decide change ---
        let change_opt = calc_change(&selected_input_utxos, pay_value, fee_rate_sat_vb)?;

        // --- build the transaction ---
        let mut outputs = pay_outs;
        if let Some(change_amt) = change_opt {
            outputs.push(TxOut {
                value: change_amt,
                script_pubkey: signer.get_script_pubkey(),
            });
        }

        let inputs: Vec<TxIn> = selected_input_utxos
            .iter()
            .map(|u| TxIn {
                previous_output: u.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xFFFFFFFD), // opt‑in RBF (BIP‑125)
                witness: Witness::new(),
            })
            .collect();

        let unsigned = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        let selected_utxos: Vec<InputUtxo> =
            selected_input_utxos.iter().map(|&u| u.clone()).collect();
        let signed = signer.sign_transaction(&unsigned, &selected_utxos)?;
        btc_rpc.send_raw_transaction(&signed).await?;
        let _ = req.response_tx.send(Ok(signed.compute_txid()));
    }
    Ok(())
}
