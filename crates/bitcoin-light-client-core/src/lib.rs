pub mod hasher;
pub mod leaves;
pub mod light_client;
pub mod mmr;

use core::fmt;

use crypto_bigint::U256;
use serde::{Deserialize, Serialize};
use sol_bindings::Types::LightClientPublicInput;

use crate::hasher::{Digest, Hasher};
use crate::leaves::create_new_leaves;
use crate::leaves::{BlockLeaf, BlockLeafCompressor};
use crate::light_client::Header;
use crate::mmr::{CompactMerkleMountainRange, MMRProof};

fn validate_leaf_block_hashes(
    parent_header: &Header,
    parent_leaf: &BlockLeaf,
    parent_retarget_header: &Header,
    parent_retarget_leaf: &BlockLeaf,
) {
    assert!(
        parent_leaf.compare_by_natural_block_hash(
            &bitcoin_core_rs::get_block_hash(parent_header.as_bytes())
                .expect("Failed to get parent header block hash")
        ),
        "Parent leaf block hash {} does not match parent header block hash {}",
        hex::encode(parent_leaf.block_hash),
        hex::encode(
            bitcoin_core_rs::get_block_hash(parent_header.as_bytes())
                .expect("Failed to get parent header block hash")
        )
    );

    assert!(
        parent_retarget_leaf.compare_by_natural_block_hash(
            &bitcoin_core_rs::get_block_hash(parent_retarget_header.as_bytes())
                .expect("Failed to get parent retarget header block hash")
        ),
        "Parent retarget leaf block hash does not match parent retarget header block hash"
    );
}

#[allow(clippy::too_many_arguments)]
fn validate_mmr_proofs<H: Hasher>(
    parent_leaf_hash: &Digest,
    current_tip_leaf_hash: &Digest,
    parent_retarget_leaf_hash: &Digest,
    parent_leaf_inclusion_proof: &MMRProof,
    current_tip_leaf_inclusion_proof: &MMRProof,
    parent_retarget_leaf_inclusion_proof: &MMRProof,
    current_mmr_root: &Digest,
    previous_mmr_leaf_count: u32,
) {
    // [1] Validate parent leaf hashes match inclusion proof leaf hashes
    assert_eq!(
        parent_leaf_hash, &parent_leaf_inclusion_proof.leaf_hash,
        "Parent leaf hash does not match parent leaf inclusion proof leaf"
    );

    assert_eq!(
        current_tip_leaf_hash, &current_tip_leaf_inclusion_proof.leaf_hash,
        "Previous tip leaf hash does not match previous tip leaf inclusion proof leaf"
    );

    assert_eq!(
        parent_retarget_leaf_hash, &parent_retarget_leaf_inclusion_proof.leaf_hash,
        "Parent retarget leaf hash does not match parent retarget leaf inclusion proof leaf"
    );

    // [2] Ensure the leaf count is the same for all proofs
    assert_eq!(
        previous_mmr_leaf_count, parent_leaf_inclusion_proof.leaf_count,
        "Previous MMR leaf count does not match parent leaf count in proof"
    );

    assert_eq!(
        previous_mmr_leaf_count, current_tip_leaf_inclusion_proof.leaf_count,
        "Previous MMR leaf count does not match previous tip leaf count in proof"
    );

    assert_eq!(
        previous_mmr_leaf_count, parent_retarget_leaf_inclusion_proof.leaf_count,
        "Previous MMR leaf count does not match parent retarget leaf count in proof"
    );

    // [3] Verify the proofs are valid
    assert!(
        mmr::verify_mmr_proof::<H>(current_mmr_root, parent_leaf_inclusion_proof),
        "Parent leaf inclusion proof is invalid"
    );

    assert!(
        mmr::verify_mmr_proof::<H>(current_mmr_root, current_tip_leaf_inclusion_proof),
        "Previous tip leaf inclusion proof is invalid"
    );

    assert!(
        mmr::verify_mmr_proof::<H>(current_mmr_root, parent_retarget_leaf_inclusion_proof),
        "Parent retarget leaf inclusion proof is invalid"
    );
}

fn validate_reorg_conditions(
    parent_leaf: &BlockLeaf,
    current_tip_leaf: &BlockLeaf,
    parent_leaf_hash: &Digest,
    current_tip_leaf_hash: &Digest,
    disposed_leaf_hashes: &[Digest],
) {
    if parent_leaf_hash != current_tip_leaf_hash {
        assert!(
            !disposed_leaf_hashes.is_empty(),
            "Disposed leaves should not be empty for a reorg"
        );
    }

    assert!(
        current_tip_leaf.height as i64 - parent_leaf.height as i64
            == disposed_leaf_hashes.len() as i64,
        "Disposed leaves should be the difference between the previous tip leaf height and the parent leaf height"
    );
}

pub fn validate_chainwork(
    parent_leaf: &BlockLeaf,
    current_tip_leaf: &BlockLeaf,
    new_headers: &[Header],
) -> (Vec<U256>, U256) {
    let (new_chain_works, new_chain_cumulative_work) =
        light_client::calculate_cumulative_work(parent_leaf.chainwork_as_u256(), new_headers);

    if new_chain_cumulative_work <= current_tip_leaf.chainwork_as_u256() {
        panic!("New chain cumulative work is not greater than previous tip cumulative work");
    }

    (new_chain_works, new_chain_cumulative_work)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProvenLeaf {
    pub leaf: BlockLeaf,
    pub proof: MMRProof,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct VerifiedBlock {
    pub header: Header,
    pub mmr_data: ProvenLeaf,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ChainTransition {
    // Previous MMR state
    pub current_mmr_root: Digest,
    pub current_mmr_bagged_peak: Digest, // bagged peak of the old MMR, when hashed with the leaf count gives the previous MMR root

    // Blocks needed to verify the transition, with proofs that they're in the old MMR
    pub parent: VerifiedBlock,          // parent of the new chain
    pub parent_retarget: VerifiedBlock, // retarget block of the parent
    pub current_tip: ProvenLeaf,        // current tip of the old MMR

    // New chain data
    pub parent_leaf_peaks: Vec<Digest>, // peaks of the MMR with parent as the tip
    pub disposed_leaf_hashes: Vec<Digest>, // leaves that are being removed from the old MMR => all of the leaves after parent in the old MMR
    pub new_headers: Vec<Header>,
}

impl fmt::Debug for ChainTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainTransition")
            .field("current_mmr_root", &hex::encode(self.current_mmr_root))
            .field(
                "current_mmr_bagged_peak",
                &hex::encode(self.current_mmr_bagged_peak),
            )
            .field("parent", &self.parent)
            .field("parent_retarget", &self.parent_retarget)
            .field("current_tip", &self.current_tip)
            .field(
                "parent_leaf_peaks",
                &self
                    .parent_leaf_peaks
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
            )
            .field(
                "disposed_leaf_hashes",
                &self
                    .disposed_leaf_hashes
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
            )
            .field(
                "new_headers",
                &self
                    .new_headers
                    .iter()
                    .map(|h| hex::encode(h.as_bytes()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuxiliaryLightClientData {
    pub compressed_leaves: Vec<u8>,
}

impl ChainTransition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        current_mmr_root: Digest,
        current_mmr_bagged_peak: Digest,
        parent: VerifiedBlock,
        parent_retarget: VerifiedBlock,
        current_tip: ProvenLeaf,
        parent_leaf_peaks: Vec<Digest>,
        disposed_leaf_hashes: Vec<Digest>,
        new_headers: Vec<Header>,
    ) -> Self {
        Self {
            current_mmr_root,
            current_mmr_bagged_peak,
            parent,
            parent_retarget,
            current_tip,
            parent_leaf_peaks,
            disposed_leaf_hashes,
            new_headers,
        }
    }

    /// Commit to a new chain, validating the new headers are valid under PoW
    /// and that the new chain extends the previous chain from a previous header.
    /// auxiliary data is used by clients who create proofs who need to post data onchain
    pub fn verify<H: Hasher>(
        &self,
        include_auxiliary_data: bool,
    ) -> (LightClientPublicInput, Option<AuxiliaryLightClientData>) {
        // [0] Validate block hashes
        validate_leaf_block_hashes(
            &self.parent.header,
            &self.parent.mmr_data.leaf,
            &self.parent_retarget.header,
            &self.parent_retarget.mmr_data.leaf,
        );

        // [1] Precompute leaf hashes and total amount of leaves
        let parent_leaf_hash = self.parent.mmr_data.leaf.hash::<H>();
        let parent_retarget_leaf_hash = self.parent_retarget.mmr_data.leaf.hash::<H>();
        let current_tip_leaf_hash = self.current_tip.leaf.hash::<H>();

        // block heights are 0-indexed so add 1 to get the number of leaves, keep in mind this is only true if the chain begins with the genesis block
        let current_tip_chain_leaf_count = self.current_tip.leaf.height + 1;
        let parent_chain_leaf_count = self.parent.mmr_data.leaf.height + 1;

        // [2] Validate header chain
        light_client::validate_header_chain(
            self.parent.mmr_data.leaf.height,
            &self.parent.header,
            &self.parent_retarget.header,
            &self.new_headers,
        );

        // [3] Validate chainwork and get new chain works
        let (new_chain_works, _) = validate_chainwork(
            &self.parent.mmr_data.leaf,
            &self.current_tip.leaf,
            &self.new_headers,
        );

        // [4] Create new leaves
        let new_leaves = create_new_leaves(
            &self.parent.mmr_data.leaf,
            &self.new_headers,
            &new_chain_works,
        );

        // [5] Validate MMR proofs
        validate_mmr_proofs::<H>(
            &parent_leaf_hash,
            &current_tip_leaf_hash,
            &parent_retarget_leaf_hash,
            &self.parent.mmr_data.proof,
            &self.current_tip.proof,
            &self.parent_retarget.mmr_data.proof,
            &self.current_mmr_root,
            current_tip_chain_leaf_count,
        );

        // [6-7] Validate reorg conditions
        validate_reorg_conditions(
            &self.parent.mmr_data.leaf,
            &self.current_tip.leaf,
            &parent_leaf_hash,
            &current_tip_leaf_hash,
            &self.disposed_leaf_hashes,
        );

        assert!(
            mmr::get_root::<H>(current_tip_chain_leaf_count, &self.current_mmr_bagged_peak)
                == self.current_mmr_root,
            "Previous MMR root should be the same as the bagged peak + leaf count"
        );

        // [9] validate parent MMR via passing disposed leaves and asserting the root is the previous
        let mut new_mmr: CompactMerkleMountainRange<H> = CompactMerkleMountainRange::from_peaks(
            &self.parent_leaf_peaks,
            parent_chain_leaf_count,
        );

        new_mmr.validate_mmr_transition(&self.disposed_leaf_hashes, &self.current_mmr_root);

        // [10] append the new leaves to the parent MMR
        for leaf in &new_leaves {
            new_mmr.append(&leaf.hash::<H>());
        }

        // [11] Only include new leaves
        let compressed_leaves: Vec<u8> = new_leaves.compress();

        // [12] Compute the new leaves commitment
        let new_leaves_commitment = H::hash(&compressed_leaves);

        // [13] return the Public Input to commit to witness
        let public_input = LightClientPublicInput {
            previousMmrRoot: self.current_mmr_root.into(),
            newMmrRoot: new_mmr.get_root().into(),
            compressedLeavesCommitment: new_leaves_commitment.into(),
            tipBlockLeaf: (*new_leaves.last().expect("New leaves should not be empty")).into(),
        };

        if include_auxiliary_data {
            (
                public_input,
                Some(AuxiliaryLightClientData { compressed_leaves }),
            )
        } else {
            (public_input, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use accumulators::mmr::MMR as ClientMMR;
    use bitcoin_core_rs::get_retarget_height;
    use hasher::Keccak256Hasher;
    use leaves::get_genesis_leaf;
    use mmr::tests::{
        client_mmr_proof_to_circuit_mmr_proof, create_keccak256_client_mmr, digest_to_hex,
    };
    use mmr::CompactMerkleMountainRange;
    use test_data_utils::{EXHAUSTIVE_TEST_HEADERS, TEST_BCH_HEADERS, TEST_HEADERS};

    #[test]
    fn validate_headers_available() {
        assert!(!TEST_HEADERS.is_empty(), "Headers should be loaded");
    }

    // create a baby MMR from genesis (no other leaves)
    async fn create_from_genesis() -> (
        usize,
        Header,
        BlockLeaf,
        ClientMMR,
        CompactMerkleMountainRange<Keccak256Hasher>,
    ) {
        let genesis_header = TEST_HEADERS[0].1;
        let genesis_leaf = get_genesis_leaf();
        let mut client_mmr = create_keccak256_client_mmr();
        let mut mmr: mmr::CompactMerkleMountainRange<Keccak256Hasher> =
            mmr::CompactMerkleMountainRange::new();

        let genesis_leaf_hash = genesis_leaf.hash::<Keccak256Hasher>();
        let append_result = client_mmr
            .append(digest_to_hex(&genesis_leaf_hash))
            .await
            .unwrap();

        let genesis_client_index = append_result.element_index;

        mmr.append(&genesis_leaf_hash);
        (
            genesis_client_index,
            Header(genesis_header),
            genesis_leaf,
            client_mmr,
            mmr,
        )
    }

    struct InitialMMR {
        pub last_leaf_append_element_index: usize,
        pub last_header: Header,
        pub last_leaf: BlockLeaf,
        pub last_header_retarget_height: usize,
        pub last_header_retarget_header: Header,
        pub last_header_retarget_leaf: BlockLeaf,
        pub last_header_retarget_element_index: usize,
        pub client_mmr: ClientMMR,
        pub mmr: CompactMerkleMountainRange<Keccak256Hasher>,
    }

    async fn create_from_bch_fork() -> InitialMMR {
        let genesis_leaf = get_genesis_leaf();
        let genesis_leaf_hash = genesis_leaf.hash::<Keccak256Hasher>();

        // create leaves for each header

        let start = Instant::now();
        let new_headers = EXHAUSTIVE_TEST_HEADERS[1..=478558]
            .iter()
            .map(|(_, header)| Header(*header))
            .collect::<Vec<_>>();

        let (new_chain_works, _) = validate_chainwork(&genesis_leaf, &genesis_leaf, &new_headers);

        let new_leaves = create_new_leaves(&genesis_leaf, &new_headers, &new_chain_works);

        let last_header_retarget_height =
            get_retarget_height(new_leaves.last().unwrap().height) as usize;
        println!(
            "[info] Last header retarget height: {}",
            last_header_retarget_height
        );
        let last_header_retarget_header = Header(new_headers[last_header_retarget_height - 1].0);
        let last_header_retarget_leaf = new_leaves[last_header_retarget_height - 1];

        // now append the leaves to the MMR
        let mut client_mmr = create_keccak256_client_mmr();
        let mut mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();

        mmr.append(&genesis_leaf_hash);

        let mut last_append_result = client_mmr
            .append(digest_to_hex(&genesis_leaf_hash))
            .await
            .unwrap();

        let mut last_header_retarget_element_index = 0;
        for leaf in new_leaves.iter() {
            let leaf_hash = leaf.hash::<Keccak256Hasher>();
            mmr.append(&leaf_hash);
            last_append_result = client_mmr.append(digest_to_hex(&leaf_hash)).await.unwrap();

            if leaf.height as usize == last_header_retarget_height {
                last_header_retarget_element_index = last_append_result.element_index;
            }
        }

        assert!(last_header_retarget_element_index != 0);

        println!(
            "Time to append {} leaves: {:#?}",
            new_leaves.len(),
            start.elapsed()
        );

        InitialMMR {
            last_leaf_append_element_index: last_append_result.element_index,
            last_header: *new_headers.last().unwrap(),
            last_leaf: *new_leaves.last().unwrap(),
            last_header_retarget_height,
            last_header_retarget_header,
            last_header_retarget_leaf,
            last_header_retarget_element_index,
            client_mmr,
            mmr,
        }
    }

    #[tokio::test]
    // Test committing 3 new blocks to an existing chain
    async fn test_basic_chain_extension() {
        let (genesis_client_index, genesis_header, genesis_leaf, client_mmr, mmr) =
            create_from_genesis().await;
        let new_headers: Vec<Header> = TEST_HEADERS[1..4]
            .iter()
            .map(|(_, header)| Header(*header))
            .collect();

        let public_input = ChainTransition::new(
            mmr.get_root(),
            mmr.bag_peaks().unwrap(),
            VerifiedBlock {
                header: genesis_header,
                mmr_data: ProvenLeaf {
                    leaf: genesis_leaf,
                    proof: client_mmr_proof_to_circuit_mmr_proof(
                        &client_mmr
                            .get_proof(genesis_client_index, None)
                            .await
                            .unwrap(),
                    ),
                },
            },
            VerifiedBlock {
                header: genesis_header,
                mmr_data: ProvenLeaf {
                    leaf: genesis_leaf,
                    proof: client_mmr_proof_to_circuit_mmr_proof(
                        &client_mmr
                            .get_proof(genesis_client_index, None)
                            .await
                            .unwrap(),
                    ),
                },
            },
            ProvenLeaf {
                leaf: genesis_leaf,
                proof: client_mmr_proof_to_circuit_mmr_proof(
                    &client_mmr
                        .get_proof(genesis_client_index, None)
                        .await
                        .unwrap(),
                ),
            },
            mmr.peaks,
            vec![],
            new_headers.to_vec(),
        )
        .verify::<Keccak256Hasher>(false);

        println!("Public input: {:?}", public_input);
        // Verify the new MMR root and public inputs
    }

    // Create an MMR up to the bch fork block (block 478558), then commit to 10 BCH blocks, then dispose of the 10 BCH blocks, simultaneously commiting to 11 bitcoin blocks
    // Then validate the new MMR root and public inputs
    #[tokio::test]
    async fn test_bch_chain_extension_then_overwrite() {
        let client_mmr_state = create_from_bch_fork().await;

        let pre_bch_mmr_leaf_element_index = client_mmr_state.last_leaf_append_element_index;

        let parent_leaf = client_mmr_state.last_leaf;
        let parent_header = client_mmr_state.last_header;

        let pre_bch_peaks = client_mmr_state.mmr.peaks.clone();

        let mut client_mmr = client_mmr_state.client_mmr;
        let mut circuit_mmr = client_mmr_state.mmr;

        // 10 bch headers
        let bch_headers = TEST_BCH_HEADERS[0..10]
            .iter()
            .map(|(_, header)| Header(*header))
            .collect::<Vec<_>>();

        let (bch_chain_works, _) = validate_chainwork(
            &client_mmr_state.last_leaf,
            &client_mmr_state.last_leaf,
            &bch_headers,
        );

        let bch_leaves =
            create_new_leaves(&client_mmr_state.last_leaf, &bch_headers, &bch_chain_works);

        // add the BCH leaves to the MMR

        let mut last_appended_element_index = client_mmr_state.last_leaf_append_element_index;
        let mut last_appended_leaf = client_mmr_state.last_leaf;
        let mut last_appended_header = client_mmr_state.last_header;
        for (i, leaf) in bch_leaves.iter().enumerate() {
            let append_result = client_mmr
                .append(digest_to_hex(&leaf.hash::<Keccak256Hasher>()))
                .await
                .unwrap();
            circuit_mmr.append(&leaf.hash::<Keccak256Hasher>());
            last_appended_element_index = append_result.element_index;
            last_appended_leaf = *leaf;
            last_appended_header = bch_headers[i];
        }

        // now get proofs for parent leaf and previous tip leaf
        let parent_leaf_proof = client_mmr
            .get_proof(pre_bch_mmr_leaf_element_index, None)
            .await
            .unwrap();

        let current_tip_leaf_proof = client_mmr
            .get_proof(last_appended_element_index, None)
            .await
            .unwrap();

        let current_tip_leaf = last_appended_leaf;
        let current_tip_header = last_appended_header;

        let parent_retarget_height = get_retarget_height(parent_leaf.height) as usize;
        println!("Parent retarget height: {}", parent_retarget_height);
        println!(
            "Last header retarget height: {}",
            client_mmr_state.last_header_retarget_height
        );
        assert!(parent_retarget_height == client_mmr_state.last_header_retarget_height);

        println!(
            "[grabbed] Last header retarget element index: {}",
            client_mmr_state.last_header_retarget_element_index
        );

        let parent_retarget_header = client_mmr_state.last_header_retarget_header;
        let parent_retarget_leaf = client_mmr_state.last_header_retarget_leaf;

        let parent_retarget_proof = client_mmr
            .get_proof(client_mmr_state.last_header_retarget_element_index, None)
            .await
            .unwrap();

        let parent_retarget_observed_leaf_hash = parent_retarget_proof.element_hash.clone();

        println!(
            "Parent retarget observed leaf hash: {}",
            &parent_retarget_observed_leaf_hash
        );

        println!(
            "Correct parent retarget leaf hash: {}",
            digest_to_hex(&parent_retarget_leaf.hash::<Keccak256Hasher>())
        );

        assert!(
            parent_retarget_observed_leaf_hash
                == digest_to_hex(&parent_retarget_leaf.hash::<Keccak256Hasher>()),
            "Parent retarget proof is not for the correct leaf"
        );

        let current_mmr_root = circuit_mmr.get_root();
        let current_mmr_bagged_peak = circuit_mmr.bag_peaks().unwrap();

        let btc_headers = EXHAUSTIVE_TEST_HEADERS[478559..478559 + 11]
            .iter()
            .map(|(_, header)| Header(*header))
            .collect::<Vec<_>>();

        let public_input = ChainTransition::new(
            current_mmr_root,
            current_mmr_bagged_peak,
            VerifiedBlock {
                header: parent_header,
                mmr_data: ProvenLeaf {
                    leaf: parent_leaf,
                    proof: client_mmr_proof_to_circuit_mmr_proof(&parent_leaf_proof),
                },
            },
            VerifiedBlock {
                header: parent_retarget_header,
                mmr_data: ProvenLeaf {
                    leaf: parent_retarget_leaf,
                    proof: client_mmr_proof_to_circuit_mmr_proof(&parent_retarget_proof),
                },
            },
            ProvenLeaf {
                leaf: current_tip_leaf,
                proof: client_mmr_proof_to_circuit_mmr_proof(&current_tip_leaf_proof),
            },
            pre_bch_peaks,
            bch_leaves
                .iter()
                .map(|l| l.hash::<Keccak256Hasher>())
                .collect(),
            btc_headers,
        )
        .verify::<Keccak256Hasher>(false);

        println!("Public input: {:?}", public_input);
    }
}
