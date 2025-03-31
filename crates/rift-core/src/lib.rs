#![allow(clippy::too_many_arguments)]

pub mod payments;
pub mod spv;
pub mod vaults;

use crate::spv::{generate_bitcoin_txn_hash, verify_bitcoin_txn_merkle_proof, MerkleProofStep};

use crate::payments::validate_bitcoin_payment;

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin_core_rs::get_block_hash;
use bitcoin_light_client_core::light_client::Header;
use serde::{Deserialize, Serialize};
use sol_bindings::Types::{
    DepositVault, LightClientPublicInput, ProofPublicInput, ProofType, SwapPublicInput,
};

use vaults::hash_deposit_vault;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiftTransaction {
    // no segwit data serialized bitcoin transaction
    pub txn: Vec<u8>,
    // the vaults reserved for this transaction
    pub reserved_vault: DepositVault,
    // block header where the txn is included
    pub block_header: Header,
    // merkle proof of the txn hash in the block
    pub txn_merkle_proof: Vec<MerkleProofStep>,
}

impl RiftTransaction {
    pub fn verify(&self) -> SwapPublicInput {
        let block_header = self.block_header.as_bytes();

        // [0] Validate Bitcoin merkle proof of the transaction hash
        let block_header_merkle_root = deserialize::<bitcoin::block::Header>(block_header)
            .expect("Failed to deserialize block header")
            .merkle_root
            .to_raw_hash()
            .to_byte_array();

        let txn_hash = generate_bitcoin_txn_hash(&self.txn);
        verify_bitcoin_txn_merkle_proof(block_header_merkle_root, txn_hash, &self.txn_merkle_proof);

        // [1] Validate Bitcoin payment given the reserved deposit vault

        let vault_commitment: [u8; 32] = hash_deposit_vault(&self.reserved_vault);
        validate_bitcoin_payment(&self.txn, &self.reserved_vault, &vault_commitment)
            .expect("Failed to validate bitcoin payment");

        // [2] Construct the public input, bitcoin block hash and txid are reversed to align with network byte order
        let mut block_hash =
            get_block_hash(&self.block_header.0).expect("Failed to get block hash");

        block_hash.reverse();

        let mut txid = txn_hash;
        txid.reverse();

        SwapPublicInput {
            depositVaultCommitment: vault_commitment.into(),
            swapBitcoinBlockHash: block_hash.into(),
            swapBitcoinTxid: txid.into(),
        }
    }
}

// Combine Light Client and Rift Transaction "programs"
pub mod giga {
    use super::*;
    use bitcoin_light_client_core::{
        hasher::Keccak256Hasher, AuxiliaryLightClientData, ChainTransition,
    };

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[repr(u8)]
    pub enum RustProofType {
        SwapOnly,
        LightClientOnly,
        Combined,
    }

    impl From<ProofType> for RustProofType {
        fn from(value: ProofType) -> Self {
            if ProofType::from(0) == value {
                RustProofType::SwapOnly
            } else if ProofType::from(1) == value {
                RustProofType::LightClientOnly
            } else {
                RustProofType::Combined
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RiftProgramInput {
        pub proof_type: RustProofType,
        pub light_client_input: Option<ChainTransition>,
        pub rift_transaction_input: Option<Vec<RiftTransaction>>,
    }

    impl RiftProgramInput {
        pub fn builder() -> RiftProgramInputBuilder {
            RiftProgramInputBuilder::default()
        }
    }

    #[derive(Default)]
    pub struct RiftProgramInputBuilder {
        proof_type: Option<RustProofType>,
        light_client_input: Option<bitcoin_light_client_core::ChainTransition>,
        rift_transaction_input: Option<Vec<RiftTransaction>>,
    }

    impl RiftProgramInputBuilder {
        pub fn proof_type(mut self, proof_type: RustProofType) -> Self {
            self.proof_type = Some(proof_type);
            self
        }

        pub fn light_client_input(
            mut self,
            input: bitcoin_light_client_core::ChainTransition,
        ) -> Self {
            self.light_client_input = Some(input);
            self
        }

        pub fn rift_transaction_input(mut self, input: Vec<RiftTransaction>) -> Self {
            self.rift_transaction_input = Some(input);
            self
        }

        pub fn build(self) -> Result<RiftProgramInput, &'static str> {
            let proof_type = self.proof_type.ok_or("proof_type is required")?;

            match proof_type {
                RustProofType::LightClientOnly => {
                    let light_client_input = self
                        .light_client_input
                        .ok_or("light_client_input is required for LightClient proof type")?;
                    Ok(RiftProgramInput {
                        proof_type,
                        light_client_input: Some(light_client_input),
                        rift_transaction_input: None,
                    })
                }
                RustProofType::SwapOnly => {
                    let rift_transaction_input = self.rift_transaction_input.ok_or(
                        "rift_transaction_input is required for RiftTransaction proof type",
                    )?;
                    Ok(RiftProgramInput {
                        proof_type,
                        light_client_input: None,
                        rift_transaction_input: Some(rift_transaction_input),
                    })
                }
                RustProofType::Combined => {
                    let light_client_input = self
                        .light_client_input
                        .ok_or("light_client_input is required for Full proof type")?;
                    let rift_transaction_input = self
                        .rift_transaction_input
                        .ok_or("rift_transaction_input is required for Full proof type")?;
                    Ok(RiftProgramInput {
                        proof_type,
                        light_client_input: Some(light_client_input),
                        rift_transaction_input: Some(rift_transaction_input),
                    })
                }
            }
        }
    }

    impl RiftProgramInput {
        pub fn get_auxiliary_light_client_data(
            &self,
        ) -> (LightClientPublicInput, AuxiliaryLightClientData) {
            let (light_client_public_input, auxiliary_data) = self
                .light_client_input
                .as_ref()
                .expect("light_client_input is required for LightClient proof type")
                .verify::<Keccak256Hasher>(true);
            (light_client_public_input, auxiliary_data.unwrap())
        }

        pub fn verify(self) -> ProofPublicInput {
            match self.proof_type {
                RustProofType::SwapOnly => {
                    let rift_transaction_public_input = self
                        .rift_transaction_input
                        .expect("rift_transaction_input is required for SwapOnly proof type")
                        .iter()
                        .map(|rift_transaction| rift_transaction.verify())
                        .collect();

                    ProofPublicInput {
                        proofType: self.proof_type as u8,
                        lightClient: LightClientPublicInput::default(),
                        swaps: rift_transaction_public_input,
                    }
                }

                RustProofType::LightClientOnly => {
                    let (light_client_public_input, _) = self
                        .light_client_input
                        .expect("light_client_input is required for LightClientOnly proof type")
                        .verify::<Keccak256Hasher>(false);

                    ProofPublicInput {
                        proofType: self.proof_type as u8,
                        lightClient: light_client_public_input,
                        swaps: Vec::default(),
                    }
                }
                RustProofType::Combined => {
                    let (light_client_public_input, _) = self
                        .light_client_input
                        .expect("light_client_input is required for Combined proof type")
                        .verify::<Keccak256Hasher>(false);
                    let rift_transaction_public_input = self
                        .rift_transaction_input
                        .expect("rift_transaction_input is required for Combined proof type")
                        .iter()
                        .map(|rift_transaction| rift_transaction.verify())
                        .collect();

                    ProofPublicInput {
                        proofType: self.proof_type as u8,
                        lightClient: light_client_public_input,
                        swaps: rift_transaction_public_input,
                    }
                }
            }
        }
    }
}
