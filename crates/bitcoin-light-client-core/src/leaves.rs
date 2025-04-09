use alloy_sol_types::SolType;
use crypto_bigint::{Encoding, U256};
use hex_literal::hex;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::hasher::Hasher;
use crate::light_client::Header;

#[derive(PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Default)]
pub struct BlockLeaf {
    pub height: u32,
    pub block_hash: [u8; 32],           // Stored in reverse byte order
    pub cumulative_chainwork: [u8; 32], // Stored in reverse byte order
}

impl From<BlockLeaf> for sol_bindings::Types::BlockLeaf {
    fn from(leaf: BlockLeaf) -> Self {
        // Chainwork is stored in reverse byte order, so we need to reverse it before converting to the Uint type
        let mut cumulative_chainwork = leaf.cumulative_chainwork;
        cumulative_chainwork.reverse();
        sol_bindings::Types::BlockLeaf {
            height: leaf.height,
            blockHash: leaf.block_hash.into(),
            cumulativeChainwork: alloy_sol_types::sol_data::Uint::<256>::detokenize(
                leaf.cumulative_chainwork.into(),
            ),
        }
    }
}

const SERIALIZED_LEAF_SIZE: usize = 68;

impl BlockLeaf {
    // Block hash is stored in reverse byte order
    // Chainwork is stored in reverse byte order
    pub fn new(block_hash: [u8; 32], height: u32, cumulative_chainwork: [u8; 32]) -> Self {
        Self {
            block_hash,
            height,
            cumulative_chainwork,
        }
    }

    pub fn chainwork_as_u256(&self) -> U256 {
        U256::from_be_bytes(self.cumulative_chainwork)
    }

    pub fn natural_block_hash(&self) -> [u8; 32] {
        let mut natural_block_hash = self.block_hash;
        natural_block_hash.reverse();
        natural_block_hash
    }

    // Compare internal hash (which is always reverse byte order) to a "natural" hash (as returned by hash(header))
    pub fn compare_by_natural_block_hash(&self, other: &[u8; 32]) -> bool {
        self.natural_block_hash() == *other
    }

    pub fn hash<H: Hasher>(&self) -> [u8; 32] {
        // Concatenate all fields into a single buffer
        let mut buffer = Vec::with_capacity(32 + 32 + 32);
        buffer.extend_from_slice(self.block_hash.as_ref());

        // Left pad height to 32 bytes to match the solidity impl
        let mut padded_height = [0u8; 32];
        padded_height[28..].copy_from_slice(&self.height.to_be_bytes());
        buffer.extend_from_slice(&padded_height);

        buffer.extend_from_slice(self.cumulative_chainwork.as_ref());

        H::hash(&buffer)
    }

    pub fn serialize(&self) -> [u8; SERIALIZED_LEAF_SIZE] {
        let mut buffer = [0u8; SERIALIZED_LEAF_SIZE];
        buffer[..32].copy_from_slice(self.block_hash.as_ref());
        buffer[32..36].copy_from_slice(&self.height.to_be_bytes());
        buffer[36..].copy_from_slice(self.cumulative_chainwork.as_ref());
        buffer
    }

    pub fn deserialize(slice: &[u8]) -> Self {
        assert!(slice.len() == SERIALIZED_LEAF_SIZE);
        let block_hash: [u8; 32] = slice[..32].try_into().unwrap();
        let height = u32::from_be_bytes(slice[32..36].try_into().unwrap());
        let cumulative_chainwork: [u8; 32] = slice[36..].try_into().unwrap();
        Self::new(block_hash, height, cumulative_chainwork)
    }
}

impl fmt::Display for BlockLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BlockLeaf {{
                height: {},
                block_hash: {},
                chainwork: {}
            }}",
            self.height,
            hex::encode(self.block_hash),
            hex::encode(self.cumulative_chainwork)
        )
    }
}

impl std::fmt::Debug for BlockLeaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockLeaf")
            .field("height", &self.height)
            .field("block_hash", &hex::encode(self.block_hash))
            .field(
                "cumulative_chainwork",
                &hex::encode(self.cumulative_chainwork),
            )
            .finish()
    }
}

pub fn create_new_leaves(
    parent_leaf: &BlockLeaf,
    new_headers: &[Header],
    new_chain_works: &[U256],
) -> Vec<BlockLeaf> {
    assert_eq!(
        new_headers.len(),
        new_chain_works.len(),
        "New headers and chain works must be the same length"
    );
    new_headers
        .iter()
        .map(|header| {
            bitcoin_core_rs::get_block_hash(&header.as_bytes()).expect("Failed to get block hash")
        })
        .zip(new_chain_works.iter())
        .zip(parent_leaf.height + 1..)
        .map(|((block_hash, cumulative_chainwork), height)| {
            let chainwork_network_order = cumulative_chainwork.to_be_bytes();
            let mut block_hash_network_order = block_hash;
            block_hash_network_order.reverse();
            BlockLeaf::new(block_hash_network_order, height, chainwork_network_order)
        })
        .collect()
}

pub fn get_genesis_leaf() -> BlockLeaf {
    BlockLeaf::new(
        hex!("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
        0,
        hex!("0000000000000000000000000000000000000000000000000000000100010001"),
    )
}

pub trait BlockLeafCompressor {
    fn compress(&self) -> Vec<u8>;
}

impl BlockLeafCompressor for [BlockLeaf] {
    fn compress(&self) -> Vec<u8> {
        // TODO: This is just a serializer, use compression algorithm at some point
        self.iter().flat_map(|leaf| leaf.serialize()).collect()
    }
}

pub fn decompress_block_leaves(bytes: &[u8]) -> Vec<BlockLeaf> {
    if bytes.is_empty() || bytes.len() % SERIALIZED_LEAF_SIZE != 0 {
        panic!("Invalid number of bytes to decompress");
    }
    bytes
        .chunks_exact(SERIALIZED_LEAF_SIZE)
        .map(BlockLeaf::deserialize)
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::hasher::Keccak256Hasher;

    use super::*;
    use test_data_utils::TEST_HEADERS;

    #[test]
    fn test_compress_decompress_roundtrip() {
        // Create some test block leaves
        let leaves = vec![
            get_genesis_leaf(),
            BlockLeaf::new(
                hex!("4860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000"),
                1,
                hex!("0200020002000000000000000000000000000000000000000000000000000000"),
            ),
        ];

        // Compress the leaves
        let compressed = leaves.compress();

        // Decompress back
        let decompressed = decompress_block_leaves(&compressed);

        // Verify the roundtrip
        assert_eq!(leaves, decompressed);
    }
    #[test]
    fn test_create_new_leaves() {
        // Get genesis leaf as parent
        let parent_leaf = get_genesis_leaf();

        // Get first 4 headers after genesis
        let new_headers: Vec<Header> = TEST_HEADERS[1..5]
            .iter()
            .map(|(_, header)| Header(header.clone()))
            .collect();

        // Calculate expected chainworks
        // Each block has same target/difficulty, so each adds 4295032833 to total
        let chainworks: Vec<U256> = vec![
            U256::from_u64(4295032833 * 2), // Block 1
            U256::from_u64(4295032833 * 3), // Block 2
            U256::from_u64(4295032833 * 4), // Block 3
            U256::from_u64(4295032833 * 5), // Block 4
        ];

        // Create new leaves
        let new_leaves = create_new_leaves(&parent_leaf, &new_headers, &chainworks);

        // Validate results
        assert_eq!(new_leaves.len(), 4, "Should create 4 new leaves");

        // Validate first leaf
        assert_eq!(new_leaves[0].height, 1);
        assert_eq!(
            new_leaves[0].chainwork_as_u256(),
            U256::from_u64(4295032833 * 2)
        );

        // Validate last leaf
        assert_eq!(new_leaves[3].height, 4);
        assert_eq!(
            new_leaves[3].chainwork_as_u256(),
            U256::from_u64(4295032833 * 5)
        );
        println!("last leaf: {}", new_leaves[3]);

        // Verify block hashes match expected values from TEST_HEADERS
        for (i, leaf) in new_leaves.iter().enumerate() {
            let expected_header = &TEST_HEADERS[i + 1].1;
            let expected_hash =
                bitcoin_core_rs::get_block_hash(&Header(*expected_header).as_bytes())
                    .expect("Failed to get block hash");
            assert!(leaf.compare_by_natural_block_hash(&expected_hash));
        }
    }

    #[test]
    fn test_chainwork_as_u256() {
        let leaf = get_genesis_leaf();
        assert_eq!(leaf.chainwork_as_u256(), U256::from_u64(4295032833));
    }

    // TODO: Compare solidity hasher to rust hasher

    #[test]
    fn test_block_leaf_hash() {
        let leaf = get_genesis_leaf();
        let hash = leaf.hash::<Keccak256Hasher>();
        assert_eq!(
            hash,
            hex!("1f05e44006fa2411c12ffefe8397c210c0dd53d73d63d30afb84461df8819a92")
        );
    }
}
