use thiserror::Error;

#[derive(Error, Debug)]
pub enum RiftSdkError {
    #[error("Bitcoin RPC failed to download data: {0}")]
    BitcoinRpcError(String),

    #[error("Store failed to be utilized: {0}")]
    StoreError(String),

    #[error("Failed to initialize client MMR: {0}")]
    ClientMMRError(String),

    #[error("Failed to append leaf to MMR: {0}")]
    AppendLeafError(String),

    #[error("MMR error: {0}")]
    MMRError(String),

    #[error("Failed to create websocket provider: {0}")]
    WebsocketProviderError(String),

    #[error("Failed to get block: {0}")]
    GetBlockError(String),

    #[error("Insufficient funds")]
    InsufficientFunds,

    #[error("Header chain validation failed")]
    HeaderChainValidationFailed,

    #[error("Parent validation failed: {0}")]
    ParentValidationFailed(String),
}

pub type Result<T> = std::result::Result<T, RiftSdkError>;
