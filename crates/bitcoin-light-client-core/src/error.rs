use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(context(suffix(false)))]
#[snafu(visibility(pub))]
pub enum BitcoinLightClientError {
    #[snafu(display(
        "Parent leaf block hash {} does not match parent header block hash {}",
        hex::encode(parent_leaf_hash),
        hex::encode(parent_header_hash)
    ))]
    ParentLeafBlockHashMismatch {
        parent_leaf_hash: Vec<u8>,
        parent_header_hash: Vec<u8>,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display(
        "Parent retarget leaf block hash {} does not match parent retarget header block hash {}",
        hex::encode(parent_retarget_leaf_hash),
        hex::encode(parent_retarget_header_hash)
    ))]
    ParentRetargetLeafBlockHashMismatch {
        parent_retarget_leaf_hash: Vec<u8>,
        parent_retarget_header_hash: Vec<u8>,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display(
        "Leaf comparison for {leaf_type} check failed: expected hash {} does not match proof hash {}",
        hex::encode(expected_hash),
        hex::encode(proof_hash)
    ))]
    MMRProofLeafHashMismatch {
        leaf_type: String,
        expected_hash: Vec<u8>,
        proof_hash: Vec<u8>,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display(
        "Leaf count mismatch for {leaf_type} failed: expected count {} does not match proof count {}",
        expected_count,
        proof_count
    ))]
    MMRProofLeafCountMismatch {
        leaf_type: String,
        expected_count: u32,
        proof_count: u32,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("MMR proof validation failed for {leaf_type}"))]
    MmrProofValidationFailed {
        leaf_type: String,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Reorg validation failed: {reason}"))]
    ReorgValidationFailed {
        reason: String,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display(
        "Chainwork validation failed: new cumulative work {} is not greater than current tip work {}",
        new_work,
        current_work
    ))]
    ChainworkValidationFailed {
        new_work: String,
        current_work: String,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display(
        "MMR root validation failed: computed root {} does not match expected root {}",
        hex::encode(computed_root),
        hex::encode(expected_root)
    ))]
    MmrRootValidationFailed {
        computed_root: Vec<u8>,
        expected_root: Vec<u8>,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display(
        "Headers and chain works length mismatch: headers length {} does not match chain works length {}",
        headers_length,
        chain_works_length
    ))]
    HeadersChainWorksLengthMismatch {
        headers_length: usize,
        chain_works_length: usize,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("New leaves should not be empty"))]
    NewLeavesEmpty {
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display(
        "Invalid serialized leaf size: expected {} bytes, got {} bytes",
        expected_size,
        actual_size
    ))]
    InvalidSerializedLeafSize {
        expected_size: usize,
        actual_size: usize,
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Header chain must not be empty"))]
    HeaderChainEmpty {
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Header chain link is not connected"))]
    HeaderChainLinkNotConnected {
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Failed to validate work requirement"))]
    WorkRequirementValidationFailed {
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Header fails proof of work check"))]
    HeaderProofOfWorkFailed {
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Header proof calculation failed"))]
    HeaderProofCalculationFailed {
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display("Chainwork addition overflow"))]
    ChainworkAdditionOverflow {
        #[snafu(implicit)]
        loc: snafu::Location,
    },

    #[snafu(display(
        "Invalid peak count for compact MMR with leaf count {}: expected {} peaks, got {} peaks",
        leaf_count,
        expected_peak_count,
        actual_peak_count
    ))]
    InvalidPeakCount {
        leaf_count: u32,
        expected_peak_count: usize,
        actual_peak_count: usize,
        #[snafu(implicit)]
        loc: snafu::Location,
    },
}

impl From<bitcoin_core_rs::error::BitcoinError> for BitcoinLightClientError {
    fn from(_: bitcoin_core_rs::error::BitcoinError) -> Self {
        WorkRequirementValidationFailed.build()
    }
}

pub type Result<T> = std::result::Result<T, BitcoinLightClientError>;
