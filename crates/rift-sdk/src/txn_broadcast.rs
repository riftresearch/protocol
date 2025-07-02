use crate::WebsocketWalletProvider;
use alloy::{
    eips::BlockId,
    primitives::{Bytes, FixedBytes},
    providers::{Provider, WalletProvider},
    rpc::{
        json_rpc::ErrorPayload,
        types::{TransactionReceipt, TransactionRequest as AlloyTransactionRequest},
    },
    transports::RpcError,
};
use std::sync::Arc;
use tokio::{
    sync::{
        broadcast,
        mpsc::{channel, Receiver, Sender},
        oneshot,
    },
    task::JoinSet,
};
use tracing;

#[derive(Debug, Clone)]
pub struct RevertInfo {
    pub error_payload: ErrorPayload,
    pub debug_cli_command: String,
}

impl RevertInfo {
    pub fn new(error_payload: ErrorPayload, debug_cli_command: String) -> Self {
        Self {
            error_payload,
            debug_cli_command,
        }
    }
}

#[derive(Debug, Clone)]
pub enum TransactionExecutionResult {
    Success(Box<TransactionReceipt>),
    // Potentially recoverable
    Revert(RevertInfo),
    InvalidRequest(String),
    // Generally non-recoverable
    UnknownError(String),
}

impl TransactionExecutionResult {
    pub fn is_success(&self) -> bool {
        matches!(self, TransactionExecutionResult::Success(_))
    }
    pub fn is_revert(&self) -> bool {
        matches!(self, TransactionExecutionResult::Revert(_))
    }
    pub fn is_invalid_request(&self) -> bool {
        matches!(self, TransactionExecutionResult::InvalidRequest(_))
    }
    pub fn is_unknown_error(&self) -> bool {
        matches!(self, TransactionExecutionResult::UnknownError(_))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PreflightCheck {
    Simulate,
    None,
}

#[derive(Debug)]
struct Request {
    calldata: Bytes,
    transaction_request: AlloyTransactionRequest,
    preflight_check: PreflightCheck,
    confirmations: u64,
    // the tx part of a oneshot channel
    tx: oneshot::Sender<TransactionExecutionResult>,
}

#[derive(Debug, Clone)]
pub struct TransactionStatusUpdate {
    pub tx_hash: FixedBytes<32>,
    pub result: TransactionExecutionResult,
}

#[derive(Debug)]
pub struct TransactionBroadcaster {
    request_sender: Sender<Request>,
    status_broadcaster: broadcast::Sender<TransactionStatusUpdate>,
    confirmations: u64,
}

impl TransactionBroadcaster {
    // Helper function to check if an error is nonce-related
    fn is_nonce_error(error: &RpcError<alloy::transports::TransportErrorKind>) -> bool {
        match error {
            RpcError::ErrorResp(error_payload) => {
                let message = error_payload.message.to_lowercase();
                message.contains("nonce too low")
                    || message.contains("replacement transaction underpriced")
            }
            _ => false,
        }
    }

    // Helper function to bump gas prices for replacement transactions
    fn bump_gas_prices(tx_request: &mut AlloyTransactionRequest) {
        // Bump gas prices by 10% for replacement transactions
        if let Some(gas_price) = tx_request.gas_price {
            tx_request.gas_price = Some(gas_price + gas_price / 10);
        }
        if let Some(max_fee_per_gas) = tx_request.max_fee_per_gas {
            tx_request.max_fee_per_gas = Some(max_fee_per_gas + max_fee_per_gas / 10);
        }
        if let Some(max_priority_fee_per_gas) = tx_request.max_priority_fee_per_gas {
            tx_request.max_priority_fee_per_gas =
                Some(max_priority_fee_per_gas + max_priority_fee_per_gas / 10);
        }
    }
    pub fn new(
        wallet_rpc: Arc<WebsocketWalletProvider>,
        debug_rpc_url: String,
        confirmations: u64,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Self {
        // single-consumer channel is important here b/c nonce management is difficult and basically impossible to do concurrently - would love for this to not be true
        let (request_sender, request_receiver) = channel(128);
        let (status_broadcaster, _) = broadcast::channel::<TransactionStatusUpdate>(100);
        let status_broadcaster_clone = status_broadcaster.clone();

        // This never exits even if channel is empty, only if channel breaks/closes
        join_set.spawn(async move {
            Self::broadcast_queue(
                wallet_rpc,
                request_receiver,
                debug_rpc_url,
                status_broadcaster_clone,
            )
            .await
        });

        Self {
            request_sender,
            status_broadcaster,
            confirmations,
        }
    }

    pub fn subscribe_to_status_updates(&self) -> broadcast::Receiver<TransactionStatusUpdate> {
        self.status_broadcaster.subscribe()
    }

    // 1. Create a new transaction request
    // 2. Deprecate concept of priority (just a single pipeline)
    // 3. wait on the oneshot channel, to resolve and return the result
    pub async fn broadcast_transaction(
        &self,
        calldata: Bytes,
        transaction_request: AlloyTransactionRequest,
        preflight_check: PreflightCheck,
    ) -> eyre::Result<TransactionExecutionResult> {
        let (tx, rx) = oneshot::channel();
        let request = Request {
            calldata,
            transaction_request,
            preflight_check,
            confirmations: self.confirmations,
            tx,
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

    // Transaction broadcast flow:
    // Infinite loop, consuming request_queue:
    // 2. Simulate transaction
    // 3. Handle simulation results:
    //    - If successful: *continue*
    //    - If nonce error: Adjust nonce and retry [specify maximum number of retries [should be high]]
    //    - If insufficient funds: Return error (critical failure)
    //    - For any other errors: Return the specific error
    // 4. Broadcast the transaction
    // 5. Immediately check for nonce error or insufficient funds
    //    - If nonce error: Adjust nonce and retry
    //    - If insufficient funds: Return error (critical failure)
    //    - For any other errors: Return the specific error
    // 6. If the transaction was broadcast successfully, remove the calldata from the queue
    // 7. Handle receipt:
    //    - If successful: *continue*
    //    - For any other errors: Return the specific error decoded from the receipt
    // Open question, how to type safely return the receipt?
    async fn broadcast_queue(
        wallet_rpc: Arc<WebsocketWalletProvider>,
        mut request_receiver: Receiver<Request>,
        debug_rpc_url: String,
        status_broadcaster: broadcast::Sender<TransactionStatusUpdate>,
    ) -> eyre::Result<()> {
        let signer_address = wallet_rpc.default_signer_address();
        loop {
            let mut request = match request_receiver.recv().await {
                Some(req) => req,
                None => {
                    return Err(eyre::eyre!("TransactionBroadcaster channel closed"));
                }
            };

            let mut transaction_request = request.transaction_request.clone();
            transaction_request.from = Some(signer_address);

            let block_height = wallet_rpc.get_block_number().await?;
            let debug_cli_command = format!(
                "cast call {} --from {} --data {} --trace --block {} --rpc-url {}",
                transaction_request.to.unwrap().to().unwrap(), // TODO: Handle contract creation, (error out)
                signer_address,
                request.calldata,
                block_height,
                debug_rpc_url
            );
            match request.preflight_check {
                PreflightCheck::Simulate => {
                    let simulation_result = wallet_rpc
                        .call(transaction_request)
                        .block(BlockId::Number(block_height.into()))
                        .await;

                    let sim_error = match simulation_result.as_ref().err() {
                        Some(RpcError::ErrorResp(error_payload)) => {
                            Some(TransactionExecutionResult::Revert(RevertInfo::new(
                                error_payload.to_owned(),
                                debug_cli_command.clone(),
                            )))
                        }
                        Some(other_error) => {
                            // Handle other error types
                            Some(TransactionExecutionResult::UnknownError(
                                eyre::eyre!("Unknown simulation error: {:?}", other_error)
                                    .to_string(),
                            ))
                        }
                        None => {
                            // No error, simulation was successful
                            None
                        }
                    };
                    if let Some(sim_error) = sim_error {
                        request.tx.send(sim_error).map_err(|_| {
                            eyre::eyre!("Failed to send transaction execution result")
                        })?;
                        continue;
                    }

                    // At this point, we know the simulation was successful - no revert
                }
                PreflightCheck::None => {}
            }

            // Send TXN with retry logic for nonce errors
            const MAX_RETRIES: u32 = 10;
            let mut retry_count = 0;
            let mut tx_hash = FixedBytes::<32>::default();

            let txn_result = loop {
                let txn_result = wallet_rpc
                    .send_transaction(request.transaction_request.clone())
                    .await;

                match txn_result {
                    Ok(tx_broadcast) => {
                        tx_hash = *tx_broadcast.tx_hash();

                        let tx_receipt = tx_broadcast
                            .with_required_confirmations(request.confirmations)
                            .get_receipt()
                            .await;

                        match tx_receipt {
                            Ok(tx_receipt) => {
                                break TransactionExecutionResult::Success(Box::new(tx_receipt));
                            }
                            Err(e) => {
                                break TransactionExecutionResult::UnknownError(e.to_string());
                            }
                        }
                    }
                    Err(e) => {
                        // Check if this is a nonce error and we should retry
                        if Self::is_nonce_error(&e) && retry_count < MAX_RETRIES {
                            retry_count += 1;

                            // Log the retry attempt
                            tracing::warn!(
                                "Nonce error detected (attempt {}/{}): {:?}. Retrying with gas bump...",
                                retry_count,
                                MAX_RETRIES,
                                e
                            );

                            // Bump gas prices for replacement transaction
                            Self::bump_gas_prices(&mut request.transaction_request);

                            // For nonce too low errors, clear the nonce to let the provider refetch it
                            if let RpcError::ErrorResp(error_payload) = &e {
                                if error_payload
                                    .message
                                    .to_lowercase()
                                    .contains("nonce too low")
                                {
                                    request.transaction_request.nonce = None;
                                }
                            }

                            continue;
                        }

                        // Not a nonce error or max retries reached - classify the error for the caller
                        break match e {
                            RpcError::ErrorResp(error_payload) => {
                                TransactionExecutionResult::Revert(RevertInfo::new(
                                    error_payload.to_owned(),
                                    debug_cli_command,
                                ))
                            }
                            _ => TransactionExecutionResult::UnknownError(e.to_string()),
                        };
                    }
                }
            };

            let _ = status_broadcaster.send(TransactionStatusUpdate {
                tx_hash,
                result: txn_result.clone(),
            });

            request
                .tx
                .send(txn_result)
                .map_err(|_| eyre::eyre!("Failed to send transaction execution result"))?;
        }
    }
}
