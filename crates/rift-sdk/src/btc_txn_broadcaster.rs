use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::{ScriptBuf, Transaction, TxOut, Txid};
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        oneshot,
    },
    task::JoinSet,
};

use crate::bitcoin_utils::AsyncBitcoinClient;

/// A trait for signing transactions from a Bitcoin wallet
/// the P2WPKHBitcoinWallet should implement this trait
pub trait BitcoinSigner {
    fn sign_transaction(&self, tx: &Transaction) -> eyre::Result<Transaction>;
    fn get_script_pubkey(&self) -> ScriptBuf;
}

#[async_trait]
pub trait BitcoinTransactionBroadcasterTrait {
    async fn new<S: BitcoinSigner + Send + 'static>(
        btc_rpc: Arc<AsyncBitcoinClient>,
        btc_signer: S,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Self;
    /// Build and broadcasts a transaction from the given outputs by selecting inputs and adding change outputs
    /// Note that this will not wait for the transaction to be mined, just for the broadcast to succeed/fail
    async fn broadcast_transaction(&self, tx_outs: &[TxOut]) -> eyre::Result<Txid>;
    /// Returns true if the transaction is payable by the wallet (enough inputs)
    async fn can_fund_transaction(&self, tx: &[TxOut]) -> eyre::Result<bool>;
}

#[derive(Debug)]
struct Request {
    tx_outs: Vec<TxOut>,
}

pub struct BitcoinTransactionBroadcaster {
    request_sender: Sender<Request>,
}

#[async_trait]
impl BitcoinTransactionBroadcasterTrait for BitcoinTransactionBroadcaster {
    async fn new<S: BitcoinSigner + Send + 'static>(
        btc_rpc: Arc<AsyncBitcoinClient>,
        btc_signer: S,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Self {
        let (request_sender, request_receiver) = channel(128);

        // This never exits even if channel is empty, only if channel breaks/closes
        join_set.spawn(async move {
            consume_broadcast_queue(btc_rpc, btc_signer, request_receiver).await
        });

        Self { request_sender }
    }

    async fn broadcast_transaction(&self, tx_outs: &[TxOut]) -> eyre::Result<Txid> {
        let (tx, rx) = oneshot::channel();
        let request = Request {
            tx_outs: tx_outs.to_vec(),
        };

        // Send the request into the bounded channel (capacity 128)
        self.request_sender
            .send(request)
            .await
            .map_err(|_| eyre::eyre!("Failed to enqueue the transaction request"))?;

        // If there's an unhandled error, this will just get bubbled
        let result = rx.await?;
        Ok(result)
    }

    async fn can_fund_transaction(&self, tx: &[TxOut]) -> eyre::Result<bool> {
        // TODO: implement
        Ok(true)
    }
}

/// Private implementation detail that runs indefinitely, consuming request_receiver
async fn consume_broadcast_queue<S: BitcoinSigner>(
    btc_rpc: Arc<AsyncBitcoinClient>,
    btc_signer: S,
    mut request_receiver: Receiver<Request>,
) -> eyre::Result<()> {
    while let Some(request) = request_receiver.recv().await {
        // TODO: Implement the actual broadcasting logic
    }
    Ok(())
}
