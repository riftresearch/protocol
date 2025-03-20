// this is private to avoid exposing unwanted types to the crate root
mod internal_solidity_types {

    #![allow(missing_docs)]

    use alloy_sol_types::sol;
    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default)]
        RiftExchange,
        "../../contracts/artifacts/RiftExchange.json"
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
            TypeExposer,
            "../../contracts/artifacts/TypeExposer.json"
        );
    }
}

// Re-export the nonpublic types under a specific module
pub mod nonpublic {
    use super::*;
    pub use internal_solidity_types::nonpublic_types::Types;
}

// Re-export the public types at root
pub use internal_solidity_types::Types;

pub use internal_solidity_types::RiftExchange;
