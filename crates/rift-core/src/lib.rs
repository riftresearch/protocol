#![allow(clippy::too_many_arguments)]

pub mod error;
pub mod order_hasher;
pub mod payments;
pub mod spv;

use crate::error::*;
use crate::spv::{generate_bitcoin_txn_hash, verify_bitcoin_txn_merkle_proof, MerkleProofStep};

use crate::payments::validate_bitcoin_payments;

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin_core_rs::get_natural_block_hash;
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
    pub fn verify(&self) -> Result<Vec<PaymentPublicInput>> {
        let block_header = self.block_header.as_bytes();

        // [0] Validate Bitcoin merkle proof of the transaction hash
        let block_header_merkle_root = deserialize::<bitcoin::block::Header>(block_header)
            .map_err(|e| {
                HeaderDeserializationFailed {
                    header_bytes: block_header.to_vec(),
                    source: e,
                }
                .build()
            })?
            .merkle_root
            .to_raw_hash()
            .to_byte_array();

        let txn_hash = generate_bitcoin_txn_hash(&self.txn);
        verify_bitcoin_txn_merkle_proof(
            block_header_merkle_root,
            txn_hash,
            &self.txn_merkle_proof,
        )?;

        // [1] Validate Bitcoin payment given the reserved deposit vault
        let all_order_hashes =
            validate_bitcoin_payments(&self.txn, &self.paid_orders, self.op_return_output_index)?;

        // [2] Construct the public input, bitcoin block hash and txid are reversed to align with network byte order
        let mut block_hash = get_natural_block_hash(&self.block_header.0);
        block_hash.reverse();

        let mut txid = txn_hash;
        txid.reverse();

        Ok(self
            .order_indices
            .iter()
            .map(|index| PaymentPublicInput {
                orderHash: all_order_hashes[*index].into(),
                paymentBitcoinBlockHash: block_hash.into(),
                paymentBitcoinTxid: txid.into(),
            })
            .collect())
    }
}

// Combine Light Client and Rift Transaction "programs"
pub mod giga {
    use super::*;
    use crate::error::{
        BuilderValidationFailed, LightClientVerificationFailed, MissingAuxiliaryData,
        PaymentValidationFailed,
    };
    use bitcoin_light_client_core::{
        hasher::Keccak256Hasher, AuxiliaryLightClientData, ChainTransition,
    };
    use snafu::OptionExt;

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
    pub enum RiftProgramInput {
        SwapOnly {
            transactions: Vec<OrderFillingTransaction>,
        },
        LightClientOnly {
            chain_transition: ChainTransition,
        },
        Combined {
            chain_transition: ChainTransition,
            transactions: Vec<OrderFillingTransaction>,
        },
    }

    impl RiftProgramInput {
        pub fn swap_only(transactions: Vec<OrderFillingTransaction>) -> Self {
            RiftProgramInput::SwapOnly { transactions }
        }

        pub fn light_client_only(chain_transition: ChainTransition) -> Self {
            RiftProgramInput::LightClientOnly { chain_transition }
        }

        pub fn combined(
            chain_transition: ChainTransition,
            transactions: Vec<OrderFillingTransaction>,
        ) -> Self {
            RiftProgramInput::Combined {
                chain_transition,
                transactions,
            }
        }

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

        pub fn build(self) -> Result<RiftProgramInput> {
            let proof_type = self.proof_type.context(ProofTypeRequired)?;

            match proof_type {
                RustProofType::LightClientOnly => {
                    let light_client_input =
                        self.light_client_input.context(BuilderValidationFailed {
                            reason: "light_client_input is required for LightClient proof type"
                                .to_string(),
                        })?;
                    Ok(RiftProgramInput::light_client_only(light_client_input))
                }
                RustProofType::SwapOnly => {
                    let order_filling_transaction_input = self
                        .order_filling_transaction_input
                        .context(BuilderValidationFailed {
                            reason: "order_filling_transaction_input is required for RiftTransaction proof type".to_string()
                        })?;
                    Ok(RiftProgramInput::swap_only(order_filling_transaction_input))
                }
                RustProofType::Combined => {
                    let light_client_input =
                        self.light_client_input.context(BuilderValidationFailed {
                            reason: "light_client_input is required for Full proof type"
                                .to_string(),
                        })?;
                    let order_filling_transaction_input = self
                        .order_filling_transaction_input
                        .context(BuilderValidationFailed {
                            reason:
                                "order_filling_transaction_input is required for Full proof type"
                                    .to_string(),
                        })?;
                    Ok(RiftProgramInput::combined(
                        light_client_input,
                        order_filling_transaction_input,
                    ))
                }
            }
        }
    }

    impl RiftProgramInput {
        pub fn get_auxiliary_light_client_data(
            &self,
        ) -> Result<(LightClientPublicInput, AuxiliaryLightClientData)> {
            match self {
                RiftProgramInput::LightClientOnly { chain_transition }
                | RiftProgramInput::Combined {
                    chain_transition, ..
                } => {
                    let (light_client_public_input, auxiliary_data) = chain_transition
                        .verify::<Keccak256Hasher>(true)
                        .map_err(|_| LightClientVerificationFailed.build())?;
                    let aux_data = auxiliary_data.context(MissingAuxiliaryData)?;
                    Ok((light_client_public_input, aux_data))
                }
                RiftProgramInput::SwapOnly { .. } => Err(PaymentValidationFailed {
                    reason: "Cannot get light client data from SwapOnly proof".to_string(),
                }
                .build()),
            }
        }

        pub fn get_proof_type(&self) -> RustProofType {
            match self {
                RiftProgramInput::SwapOnly { .. } => RustProofType::SwapOnly,
                RiftProgramInput::LightClientOnly { .. } => RustProofType::LightClientOnly,
                RiftProgramInput::Combined { .. } => RustProofType::Combined,
            }
        }

        pub fn verify(self) -> Result<ProofPublicInput> {
            match self {
                RiftProgramInput::SwapOnly { transactions } => {
                    let payment_public_inputs = transactions
                        .iter()
                        .map(|order_filling_transaction| order_filling_transaction.verify())
                        .collect::<Result<Vec<_>>>()?
                        .into_iter()
                        .flatten()
                        .collect();

                    Ok(ProofPublicInput {
                        proofType: RustProofType::SwapOnly as u8,
                        lightClient: LightClientPublicInput::default(),
                        payments: payment_public_inputs,
                    })
                }

                RiftProgramInput::LightClientOnly { chain_transition } => {
                    let (light_client_public_input, _) = chain_transition
                        .verify::<Keccak256Hasher>(false)
                        .map_err(|_| LightClientVerificationFailed.build())?;

                    Ok(ProofPublicInput {
                        proofType: RustProofType::LightClientOnly as u8,
                        lightClient: light_client_public_input,
                        payments: Vec::default(),
                    })
                }

                RiftProgramInput::Combined {
                    chain_transition,
                    transactions,
                } => {
                    let (light_client_public_input, _) = chain_transition
                        .verify::<Keccak256Hasher>(false)
                        .map_err(|_| LightClientVerificationFailed.build())?;

                    let payment_public_inputs = transactions
                        .iter()
                        .map(|order_filling_transaction| order_filling_transaction.verify())
                        .collect::<Result<Vec<_>>>()?
                        .into_iter()
                        .flatten()
                        .collect();

                    Ok(ProofPublicInput {
                        proofType: RustProofType::Combined as u8,
                        lightClient: light_client_public_input,
                        payments: payment_public_inputs,
                    })
                }
            }
        }
    }
}
