use alloy::{
    eips::BlockId,
    primitives::Bytes,
    providers::{Provider, WalletProvider},
    rpc::{
        json_rpc::ErrorPayload,
        types::{TransactionReceipt, TransactionRequest as AlloyTransactionRequest},
    },
    transports::RpcError,
};
use rift_sdk::WebsocketWalletProvider;
use std::sync::Arc;
use tokio::{
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot,
    },
    task::JoinSet,
};

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
    // the tx part of a oneshot channel
    tx: oneshot::Sender<TransactionExecutionResult>,
}

#[derive(Debug)]
pub struct TransactionBroadcaster {
    request_sender: UnboundedSender<Request>,
}

impl TransactionBroadcaster {
    pub fn new(
        wallet_rpc: Arc<WebsocketWalletProvider>,
        debug_rpc_url: String,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Self {
        // Channel is important, here b/c nonce management is difficult and basically impossible to do concurrently - would love for this to not be true
        let (request_sender, request_receiver) = unbounded_channel();

        // This never exits even if channel is empty, only if channel breaks/closes
        join_set.spawn(async move {
            Self::broadcast_queue(wallet_rpc, request_receiver, debug_rpc_url).await
        });

        Self { request_sender }
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
            tx,
        };

        // Send the request into the unbounded channel
        self.request_sender
            .send(request)
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
        mut request_receiver: UnboundedReceiver<Request>,
        debug_rpc_url: String,
    ) -> eyre::Result<()> {
        let signer_address = wallet_rpc.default_signer_address();
        loop {
            let request = match request_receiver.recv().await {
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
                        .call(&transaction_request)
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

            // Send TXN
            let txn_result = wallet_rpc
                .send_transaction(request.transaction_request)
                .await;

            let txn_result = match txn_result {
                Ok(tx_broadcast) => {
                    let tx_receipt = tx_broadcast.get_receipt().await;

                    match tx_receipt {
                        Ok(tx_receipt) => TransactionExecutionResult::Success(Box::new(tx_receipt)),
                        Err(e) => TransactionExecutionResult::UnknownError(e.to_string()),
                    }
                }
                Err(e) => match e {
                    RpcError::ErrorResp(error_payload) => TransactionExecutionResult::Revert(
                        RevertInfo::new(error_payload.to_owned(), debug_cli_command),
                    ),
                    _ => TransactionExecutionResult::UnknownError(e.to_string()),
                },
            };

            request
                .tx
                .send(txn_result)
                .map_err(|_| eyre::eyre!("Failed to send transaction execution result"))?;
        }
        Ok(())
    }
}
