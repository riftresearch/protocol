#![allow(clippy::too_many_arguments)]

pub mod order_hasher;
pub mod payments;
pub mod spv;

use crate::spv::{generate_bitcoin_txn_hash, verify_bitcoin_txn_merkle_proof, MerkleProofStep};

use crate::payments::validate_bitcoin_payments;

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin_core_rs::get_block_hash;
use bitcoin_light_client_core::light_client::Header;
use serde::{Deserialize, Serialize};
use sol_bindings::{
    LightClientPublicInput, Order, PaymentPublicInput, ProofPublicInput, ProofType,
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrderFillingTransaction {
    // no segwit data serialized bitcoin transaction
    pub txn: Vec<u8>,
    // block header where the txn is included
    pub block_header: Header,
    // merkle proof of the txn hash in the block
    pub txn_merkle_proof: Vec<MerkleProofStep>,
    // the index of the OP_RETURN output in the transaction
    pub op_return_output_index: usize,
    // the orders being paid for in this transaction
    pub paid_orders: Vec<Order>,
    // The order indices (relative to the paid_orders vector) we want to commit to in this proof
    pub order_indices: Vec<usize>,
}

impl OrderFillingTransaction {
    pub fn verify(&self) -> Vec<PaymentPublicInput> {
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
        let all_order_hashes =
            validate_bitcoin_payments(&self.txn, &self.paid_orders, self.op_return_output_index)
                .expect("Failed to validate bitcoin payment");

        // [2] Construct the public input, bitcoin block hash and txid are reversed to align with network byte order
        let mut block_hash =
            get_block_hash(&self.block_header.0).expect("Failed to get block hash");

        block_hash.reverse();

        let mut txid = txn_hash;
        txid.reverse();

        self.order_indices
            .iter()
            .map(|index| PaymentPublicInput {
                orderHash: all_order_hashes[*index].into(),
                paymentBitcoinBlockHash: block_hash.into(),
                paymentBitcoinTxid: txid.into(),
            })
            .collect()
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
        pub order_filling_transaction_input: Option<Vec<OrderFillingTransaction>>,
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
        order_filling_transaction_input: Option<Vec<OrderFillingTransaction>>,
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

        pub fn order_filling_transaction_input(
            mut self,
            input: Vec<OrderFillingTransaction>,
        ) -> Self {
            self.order_filling_transaction_input = Some(input);
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
                        order_filling_transaction_input: None,
                    })
                }
                RustProofType::SwapOnly => {
                    let order_filling_transaction_input = self
                        .order_filling_transaction_input
                        .ok_or(
                            "order_filling_transaction_input is required for RiftTransaction proof type",
                        )?;
                    Ok(RiftProgramInput {
                        proof_type,
                        light_client_input: None,
                        order_filling_transaction_input: Some(order_filling_transaction_input),
                    })
                }
                RustProofType::Combined => {
                    let light_client_input = self
                        .light_client_input
                        .ok_or("light_client_input is required for Full proof type")?;
                    let order_filling_transaction_input = self
                        .order_filling_transaction_input
                        .ok_or("order_filling_transaction_input is required for Full proof type")?;
                    Ok(RiftProgramInput {
                        proof_type,
                        light_client_input: Some(light_client_input),
                        order_filling_transaction_input: Some(order_filling_transaction_input),
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
                    let payment_public_inputs = self
                        .order_filling_transaction_input
                        .expect(
                            "order_filling_transaction_input is required for SwapOnly proof type",
                        )
                        .iter()
                        .flat_map(|order_filling_transaction| order_filling_transaction.verify())
                        .collect();

                    ProofPublicInput {
                        proofType: self.proof_type as u8,
                        lightClient: LightClientPublicInput::default(),
                        payments: payment_public_inputs,
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
                        payments: Vec::default(),
                    }
                }
                RustProofType::Combined => {
                    let (light_client_public_input, _) = self
                        .light_client_input
                        .expect("light_client_input is required for Combined proof type")
                        .verify::<Keccak256Hasher>(false);
                    let payment_public_inputs = self
                        .order_filling_transaction_input
                        .expect(
                            "order_filling_transaction_input is required for Combined proof type",
                        )
                        .iter()
                        .flat_map(|order_filling_transaction| order_filling_transaction.verify())
                        .collect();

                    ProofPublicInput {
                        proofType: self.proof_type as u8,
                        lightClient: light_client_public_input,
                        payments: payment_public_inputs,
                    }
                }
            }
        }
    }
}
