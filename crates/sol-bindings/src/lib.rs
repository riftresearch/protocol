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

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
        MappingWhitelist,
        "../../contracts/artifacts/MappingWhitelist.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
        BitcoinLightClient,
        "../../contracts/artifacts/BitcoinLightClient.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
        RiftExchange,
        "../../contracts/artifacts/RiftExchange.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
        RiftAuctionAdaptor,
        "../../contracts/artifacts/RiftAuctionAdaptor.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
        Bundler3,
        "../../contracts/artifacts/Bundler3.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
        GeneralAdapter1,
        "../../contracts/artifacts/GeneralAdapter1.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
        ParaswapAdapter,
        "../../contracts/artifacts/ParaswapAdapter.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
        ERC20,
        "../../contracts/artifacts/ERC20.json"
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

/// BTCDutchAuctionHouse with a createOrder() function that allows bypassing the auction for testing purposes.
pub use internal_solidity_types::RiftExchangeHarness::*;

pub use internal_solidity_types::BTCDutchAuctionHouse::{
    self, AuctionUpdated, BTCDutchAuctionHouseInstance, DutchAuction, DutchAuctionParams,
};

pub use internal_solidity_types::MappingWhitelist::{self, MappingWhitelistInstance};

pub use internal_solidity_types::BitcoinLightClient::BitcoinLightClientInstance;

pub use internal_solidity_types::RiftExchange::RiftExchangeInstance;

pub use internal_solidity_types::RiftAuctionAdaptor;

pub use internal_solidity_types::Bundler3;

pub use internal_solidity_types::GeneralAdapter1;

pub use internal_solidity_types::ParaswapAdapter;

pub use internal_solidity_types::ERC20::{self, ERC20Instance};
