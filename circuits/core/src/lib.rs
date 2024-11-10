pub mod btc_light_client;
pub mod constants;
pub mod lp;
pub mod payment;
pub mod sha256_merkle;
pub mod tx_hash;

use alloy_sol_types::sol;
use constants::{MAX_BLOCKS, MAX_LIQUIDITY_PROVIDERS, MAX_MERKLE_PROOF_STEPS, MAX_TX_SIZE};
use crypto_bigint::U256;
use serde::{Deserialize, Serialize};
use sha256_merkle::MerkleProofStep;

mod arrays {
    use std::{convert::TryInto, marker::PhantomData};

    use serde::{
        de::{SeqAccess, Visitor},
        ser::SerializeTuple,
        Deserialize, Deserializer, Serialize, Serializer,
    };
    pub fn serialize<S: Serializer, T: Serialize, const N: usize>(
        data: &[T; N],
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        let mut s = ser.serialize_tuple(N)?;
        for item in data {
            s.serialize_element(item)?;
        }
        s.end()
    }

    struct ArrayVisitor<T, const N: usize>(PhantomData<T>);

    impl<'de, T, const N: usize> Visitor<'de> for ArrayVisitor<T, N>
    where
        T: Deserialize<'de>,
    {
        type Value = [T; N];

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str(&format!("an array of length {}", N))
        }

        #[inline]
        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // can be optimized using MaybeUninit
            let mut data = Vec::with_capacity(N);
            for _ in 0..N {
                match (seq.next_element())? {
                    Some(val) => data.push(val),
                    None => return Err(serde::de::Error::invalid_length(N, &self)),
                }
            }
            match data.try_into() {
                Ok(arr) => Ok(arr),
                Err(_) => unreachable!(),
            }
        }
    }
    pub fn deserialize<'de, D, T, const N: usize>(deserializer: D) -> Result<[T; N], D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        deserializer.deserialize_tuple(N, ArrayVisitor::<T, N>(PhantomData))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Copy)]
pub struct CircuitPublicValues {
    pub natural_txid: [u8; 32],
    pub merkle_root: [u8; 32],
    pub lp_reservation_hash: [u8; 32],
    pub order_nonce: [u8; 32],
    pub lp_count: u64,
    pub retarget_block_hash: [u8; 32],
    pub safe_block_height: u64,
    pub safe_block_height_delta: u64,
    pub confirmation_block_height_delta: u64,
    #[serde(with = "arrays")]
    pub block_hashes: [[u8; 32]; MAX_BLOCKS],
    #[serde(with = "arrays")]
    pub block_chainworks: [[u8; 32]; MAX_BLOCKS],
    pub is_transaction_proof: bool,
}

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct ProofPublicInputs {
        bytes32 natural_txid;
        bytes32 merkle_root;
        bytes32 lp_reservation_hash;
        bytes32 order_nonce;
        uint64 lp_count;
        bytes32 retarget_block_hash;
        uint64 safe_block_height;
        uint64 safe_block_height_delta;
        uint64 confirmation_block_height_delta;
        bytes32[] block_hashes;
        uint256[] block_chainworks;
        bool is_transaction_proof;
    }

}

impl Default for CircuitPublicValues {
    fn default() -> Self {
        CircuitPublicValues {
            natural_txid: [0u8; 32],
            merkle_root: [0u8; 32],
            lp_reservation_hash: [0u8; 32],
            order_nonce: [0u8; 32],
            lp_count: 0,
            retarget_block_hash: [0u8; 32],
            safe_block_height: 0,
            safe_block_height_delta: 0,
            confirmation_block_height_delta: 0,
            block_hashes: [[0u8; 32]; MAX_BLOCKS],
            block_chainworks: [[0u8; 32]; MAX_BLOCKS],
            is_transaction_proof: false,
        }
    }
}

impl CircuitPublicValues {
    pub fn new(
        natural_txid: [u8; 32],
        merkle_root: [u8; 32],
        lp_reservation_hash: [u8; 32],
        order_nonce: [u8; 32],
        lp_count: u64,
        retarget_block_hash: [u8; 32],
        safe_block_height: u64,
        safe_block_height_delta: u64,
        confirmation_block_height_delta: u64,
        block_hashes: Vec<[u8; 32]>,
        block_chainworks: Vec<[u8; 32]>,
        is_transaction_proof: bool,
    ) -> Self {
        let mut padded_block_hashes = [[0u8; 32]; MAX_BLOCKS];
        for (i, block_hash) in block_hashes.iter().enumerate() {
            padded_block_hashes[i] = *block_hash;
        }
        let mut padded_block_chainworks = [[0u8; 32]; MAX_BLOCKS];
        for (i, block_chainwork) in block_chainworks.iter().enumerate() {
            padded_block_chainworks[i] = *block_chainwork;
        }
        Self {
            natural_txid,
            merkle_root,
            lp_reservation_hash,
            order_nonce,
            lp_count,
            retarget_block_hash,
            safe_block_height,
            safe_block_height_delta,
            confirmation_block_height_delta,
            block_hashes: padded_block_hashes,
            block_chainworks: padded_block_chainworks,
            is_transaction_proof,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct CircuitInput {
    pub public_values: CircuitPublicValues,
    #[serde(with = "arrays")]
    pub txn_data_no_segwit: [u8; MAX_TX_SIZE],
    pub utilized_txn_data_size: u64,
    pub merkle_proof: [MerkleProofStep; MAX_MERKLE_PROOF_STEPS],
    pub utilized_merkle_proof_steps: u64,
    #[serde(with = "arrays")]
    pub lp_reservation_data: [[[u8; 32]; 2]; MAX_LIQUIDITY_PROVIDERS],
    pub utilized_lp_reservation_data: u64,
    #[serde(with = "arrays")]
    pub blocks: [btc_light_client::Block; MAX_BLOCKS],
    pub utilized_blocks: u64,
    pub retarget_block: btc_light_client::Block,
}

impl CircuitInput {
    pub fn new(
        public_values: CircuitPublicValues,
        txn_data_no_segwit: Vec<u8>,
        merkle_proof: Vec<MerkleProofStep>,
        lp_reservation_data: Vec<[[u8; 32]; 2]>,
        blocks: Vec<btc_light_client::Block>,
        retarget_block: btc_light_client::Block,
    ) -> Self {
        let mut padded_txn_data_no_segwit = [0u8; MAX_TX_SIZE];
        for (i, byte) in txn_data_no_segwit.iter().enumerate() {
            padded_txn_data_no_segwit[i] = *byte;
        }

        let mut padded_merkle_proof = [MerkleProofStep::default(); MAX_MERKLE_PROOF_STEPS];
        for (i, step) in merkle_proof.iter().enumerate() {
            padded_merkle_proof[i] = *step;
        }

        let mut padded_lp_reservation_data = [[[0u8; 32]; 2]; MAX_LIQUIDITY_PROVIDERS];
        for (i, lp_data) in lp_reservation_data.iter().enumerate() {
            padded_lp_reservation_data[i] = *lp_data;
        }

        let mut padded_blocks = [btc_light_client::Block::default(); MAX_BLOCKS];
        for (i, block) in blocks.iter().enumerate() {
            padded_blocks[i] = *block;
        }

        Self {
            public_values,
            txn_data_no_segwit: padded_txn_data_no_segwit,
            utilized_txn_data_size: txn_data_no_segwit.len() as u64,
            merkle_proof: padded_merkle_proof,
            utilized_merkle_proof_steps: merkle_proof.len() as u64,
            lp_reservation_data: padded_lp_reservation_data,
            utilized_lp_reservation_data: lp_reservation_data.len() as u64,
            blocks: padded_blocks,
            utilized_blocks: blocks.len() as u64,
            retarget_block,
        }
    }
}

impl Default for CircuitInput {
    fn default() -> Self {
        Self {
            public_values: CircuitPublicValues::default(),
            txn_data_no_segwit: [0u8; MAX_TX_SIZE],
            utilized_txn_data_size: 0,
            merkle_proof: [MerkleProofStep::default(); MAX_MERKLE_PROOF_STEPS],
            utilized_merkle_proof_steps: 0,
            lp_reservation_data: [[[0u8; 32]; 2]; MAX_LIQUIDITY_PROVIDERS],
            utilized_lp_reservation_data: 0,
            blocks: [btc_light_client::Block::default(); MAX_BLOCKS],
            utilized_blocks: 0,
            retarget_block: btc_light_client::Block::default(),
        }
    }
}

pub fn validate_rift_transaction(circuit_input: CircuitInput) -> CircuitPublicValues {
    // TODO: Sync up contract public inputs + add logic to validate payment recipient + total swap output amount + aggregate vault hash
    let blocks = circuit_input.blocks[0..(circuit_input.utilized_blocks as usize)].to_vec();
    let txn_data_no_segwit = circuit_input.txn_data_no_segwit
        [0..(circuit_input.utilized_txn_data_size as usize)]
        .to_vec();
    let merkle_proof = circuit_input.merkle_proof
        [0..(circuit_input.utilized_merkle_proof_steps as usize)]
        .to_vec();
    let lp_reservation_data = circuit_input.lp_reservation_data
        [0..(circuit_input.utilized_lp_reservation_data as usize)]
        .to_vec();
    if circuit_input.public_values.is_transaction_proof {
        let mut txid = tx_hash::get_natural_txid(&txn_data_no_segwit);
        txid.reverse();

        // Transaction Hash Verification
        assert_eq!(
            txid, circuit_input.public_values.natural_txid,
            "Invalid transaction hash"
        );

        // Transaction Inclusion Verification
        sha256_merkle::assert_merkle_proof_equality(
            circuit_input.public_values.merkle_root,
            circuit_input.public_values.natural_txid,
            &merkle_proof,
        );

        // LP Hash Verification
        lp::assert_lp_hash(
            circuit_input.public_values.lp_reservation_hash,
            &lp_reservation_data,
            circuit_input.public_values.lp_count as u32,
        );

        // Payment Verification
        payment::assert_bitcoin_payment(
            &txn_data_no_segwit,
            lp_reservation_data,
            circuit_input.public_values.order_nonce,
            circuit_input.public_values.lp_count,
        );
    }

    // Block Verification
    btc_light_client::assert_blockchain(
        circuit_input.public_values.block_hashes[0..(blocks.len())].to_vec(),
        circuit_input.public_values.block_chainworks[0..(blocks.len())]
            .to_vec()
            .iter()
            .map(|x| U256::from_be_slice(x))
            .collect(),
        circuit_input.public_values.safe_block_height,
        circuit_input.public_values.retarget_block_hash,
        blocks,
        circuit_input.retarget_block,
    );

    circuit_input.public_values
}
