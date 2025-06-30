use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(context(suffix(false)))]
#[snafu(visibility(pub))]
pub enum RiftCoreError {
    #[snafu(display("Failed to deserialize header: {}", hex::encode(header_bytes)))]
    HeaderDeserializationFailed {
        header_bytes: Vec<u8>,
        #[snafu(source(false))]
        source: bitcoin::consensus::encode::Error,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Failed to deserialize transaction: {}", hex::encode(txn_bytes)))]
    TransactionDeserializationFailed {
        txn_bytes: Vec<u8>,
        #[snafu(source(false))]
        source: bitcoin::consensus::encode::Error,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Proof type is required"))]
    ProofTypeRequired {
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Transaction hash not found in merkle tree"))]
    TransactionNotInMerkleTree {
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display(
        "Merkle proof verification failed: computed root {} does not match expected root {}",
        hex::encode(computed_root),
        hex::encode(expected_root)
    ))]
    MerkleProofVerificationFailed {
        computed_root: [u8; 32],
        expected_root: [u8; 32],
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Payment validation failed: {reason}"))]
    PaymentValidationFailed {
        reason: String,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Builder validation failed: {reason}"))]
    BuilderValidationFailed {
        reason: String,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Light client verification failed"))]
    LightClientVerificationFailed {
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Missing auxiliary data in light client verification"))]
    MissingAuxiliaryData {
        #[snafu(implicit)]
        loc: snafu::Location,
    },
}

pub type Result<T> = std::result::Result<T, RiftCoreError>;
