use bitcoin_core_rs::sha256;
use serde::{Deserialize, Serialize};

pub type Sha256Digest = [u8; 32];

#[derive(Default, Serialize, Deserialize, Clone, Copy, Debug)]
pub struct MerkleProofStep {
    pub hash: Sha256Digest,
    pub right: bool,
}

pub fn generate_bitcoin_txn_merkle_proof(
    transaction_hashes: &[Sha256Digest],   // natural byte order
    target_transaction_hash: Sha256Digest, // natural byte order
) -> (Vec<MerkleProofStep>, Sha256Digest) {
    let mut current_level = transaction_hashes.to_vec();
    let mut proof: Vec<MerkleProofStep> = Vec::new();
    let mut target_index = current_level
        .iter()
        .position(|&leaf| leaf == target_transaction_hash)
        .expect("Desired leaf not found in the list of leaves");

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;

        while i < current_level.len() {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                left
            };

            let parent_hash = bitcoin_merkle_hash_pair(left, right);
            next_level.push(parent_hash);

            if i == target_index || i + 1 == target_index {
                let proof_step = if i == target_index {
                    MerkleProofStep {
                        hash: right,
                        right: true,
                    }
                } else {
                    MerkleProofStep {
                        hash: left,
                        right: false,
                    }
                };
                proof.push(proof_step);
                target_index /= 2;
            }

            i += 2;
        }

        current_level = next_level;
    }

    let merkle_root = current_level[0];
    (proof, merkle_root)
}

pub fn bitcoin_merkle_hash_pair(hash_1: Sha256Digest, hash_2: Sha256Digest) -> Sha256Digest {
    let mut combined_hashes = [0u8; 64];
    combined_hashes[..32].copy_from_slice(&hash_1);
    combined_hashes[32..].copy_from_slice(&hash_2);
    sha256(&sha256(&combined_hashes))
}

/// Validate that a proposed transaction hash is included in the merkle root
pub fn verify_bitcoin_txn_merkle_proof(
    merkle_root: Sha256Digest,
    // natural byte order
    proposed_txn_hash: Sha256Digest,
    proposed_merkle_proof: &[MerkleProofStep],
) {
    let mut current_hash: Sha256Digest = proposed_txn_hash;
    for proof_step in proposed_merkle_proof {
        if proof_step.right {
            current_hash = bitcoin_merkle_hash_pair(current_hash, proof_step.hash);
        } else {
            current_hash = bitcoin_merkle_hash_pair(proof_step.hash, current_hash);
        }
    }
    assert!(
        current_hash == merkle_root,
        "Merkle proof verification failed, current_hash: {:?}, expected merkle_root: {:?}",
        current_hash,
        merkle_root
    );
}

// returns natural byte order hash of the transaction, txn_data MUST have segwit data removed
pub fn generate_bitcoin_txn_hash(txn_data: &[u8]) -> Sha256Digest {
    sha256(&sha256(txn_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use test_data_utils::TEST_BLOCKS;

    #[test]
    fn test_bitcoin_merkle_proof_against_block_sample() {
        for block in TEST_BLOCKS.iter() {
            let txn_hashes = block
                .txdata
                .iter()
                .map(|txn| txn.compute_txid().as_raw_hash().to_byte_array().to_owned())
                .collect::<Vec<[u8; 32]>>();

            let block_merkle_root = block
                .compute_merkle_root()
                .unwrap()
                .to_raw_hash()
                .to_byte_array();

            let (proof, merkle_root) =
                generate_bitcoin_txn_merkle_proof(&txn_hashes, txn_hashes[0]);
            assert!(merkle_root == block_merkle_root, "Merkle root mismatch");
            verify_bitcoin_txn_merkle_proof(block_merkle_root, txn_hashes[0], &proof);
        }
    }
}
