// this is private to avoid exposing unwanted types to the crate root
mod internal_solidity_types {

    #![allow(missing_docs)]

    use alloy_sol_types::sol;
    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
        BTCDutchAuctionHouse,
        "../../contracts/artifacts/BTCDutchAuctionHouse.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
        RiftExchangeHarness,
        "../../contracts/artifacts/RiftExchangeHarness.json"
    );

    /// the following types are not used as public arguments in the RiftExchange contract,
    /// but can be useful for testing
    pub mod nonpublic_types {
        #![allow(missing_docs)]

        use super::*;
        sol!(
            #[derive(
                Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default,
            )]
            HelperTypes,
            "../../contracts/artifacts/HelperTypes.json"
        );
    }
}

// Re-export the nonpublic types under a specific module
pub mod nonpublic {
    use super::internal_solidity_types;
    pub use internal_solidity_types::nonpublic_types::HelperTypes::{
        BlockLeaf, DeploymentParams, MMRProof, ReleaseMMRProof,
    };
}

/// Provides the core `RiftExchangeHarness` ABI (types, functions, events).
/// This harness contains the interface used by the circuits + hypernode, independent of deployment details.
pub use internal_solidity_types::RiftExchangeHarness::*;
