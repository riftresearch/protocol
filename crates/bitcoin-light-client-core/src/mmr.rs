// This is a bare bones implementation of an MMR for use in circuit validation
// Actual storage of leaves and proof generation is left to the client
use crate::hasher::{Digest, Hasher};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug};

/// Trait for different MMR data storage strategies
pub trait MMRStorageStrategy: Clone {
    fn new() -> Self;
}

/// Minimal state for circuit verification
#[derive(Clone)]
pub struct CompactMMR {}

impl MMRStorageStrategy for CompactMMR {
    fn new() -> Self {
        CompactMMR {}
    }
}

/// Base MMR implementation that works with different storage strategies (compact or full)
pub struct MerkleMountainRange<H: Hasher, S: MMRStorageStrategy> {
    // Peaks are stored in descending order of their tree heights.
    // For example, if we have peaks representing trees of heights 3, 2, and 1,
    // they will be stored as [peak_h3, peak_h2, peak_h1]
    pub peaks: Vec<Digest>,
    // Leaf count is the number of leaves in the MMR
    pub leaf_count: u32,
    pub data: S,
    _hasher: std::marker::PhantomData<H>,
}

impl<H: Hasher, S: MMRStorageStrategy> MerkleMountainRange<H, S> {
    pub fn new() -> Self {
        Self::default()
    }

    fn update_mmr_peaks(&mut self, leaf: &Digest) {
        self.leaf_count += 1;
        let mut current_peak = *leaf;
        let t = self.leaf_count.trailing_zeros() as usize;

        for _ in 0..t {
            let left_peak = self.peaks.pop().expect("No peak to pop");
            current_peak = hash_nodes::<H>(left_peak.as_ref(), current_peak.as_ref());
        }

        self.peaks.push(current_peak);
    }

    pub fn bag_peaks(&self) -> Option<Digest> {
        bag_peaks::<H>(&self.peaks)
    }

    pub fn get_root(&self) -> Digest {
        let leaf_count = self.leaf_count;
        let bagged_peaks = self.bag_peaks().unwrap_or_else(|| panic!("No peaks found"));
        get_root::<H>(leaf_count, &bagged_peaks)
    }

    pub fn validate_mmr_transition(&self, leaf_hashes: &[Digest], expected_root: &Digest) {
        let mut new_mmr = self.clone();

        for leaf_hash in leaf_hashes {
            new_mmr.update_mmr_peaks(leaf_hash);
        }

        if new_mmr.get_root() != *expected_root {
            panic!("Invalid MMR: root mismatch");
        }
    }

    fn get_mmr_peak_heights(n: u32) -> Vec<u32> {
        let mut heights = Vec::new();
        let mut position = 0;
        let mut remaining = n;

        while remaining > 0 {
            if remaining & 1 == 1 {
                heights.push(position);
            }
            remaining >>= 1;
            position += 1;
        }

        heights
    }
}

impl<H: Hasher, S: MMRStorageStrategy> Default for MerkleMountainRange<H, S> {
    fn default() -> Self {
        Self {
            peaks: vec![],
            leaf_count: 0,
            data: S::new(),
            _hasher: std::marker::PhantomData,
        }
    }
}

// Impl for compact MMR
impl<H: Hasher> MerkleMountainRange<H, CompactMMR> {
    pub fn append(&mut self, leaf: &Digest) {
        self.update_mmr_peaks(leaf);
    }

    pub fn from_peaks(peaks: &[Digest], leaf_count: u32) -> Self {
        let expected_peak_count = Self::get_mmr_peak_heights(leaf_count).len();

        assert_eq!(
            peaks.len(),
            expected_peak_count,
            "Invalid peak count for compact MMR with leaf count {}",
            leaf_count
        );

        MerkleMountainRange {
            peaks: peaks.to_vec(),
            leaf_count,
            data: CompactMMR::new(),
            _hasher: std::marker::PhantomData,
        }
    }
}

//
// Implement Clone for the base type
impl<H: Hasher, S: MMRStorageStrategy + Clone> Clone for MerkleMountainRange<H, S> {
    fn clone(&self) -> Self {
        MerkleMountainRange {
            peaks: self.peaks.clone(),
            leaf_count: self.leaf_count,
            data: self.data.clone(),
            _hasher: std::marker::PhantomData,
        }
    }
}

impl<H: Hasher> fmt::Display for MerkleMountainRange<H, CompactMMR> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CompactMerkleMountainRange {{")?;
        writeln!(f, "  Leaf count: {}", self.leaf_count)?;
        writeln!(f, "  Peaks:")?;
        for (i, peak) in self.peaks.iter().enumerate() {
            writeln!(f, "  {}: 0x{}", i, hex::encode(peak))?;
        }
        if let Some(bagged) = self.bag_peaks() {
            writeln!(f, "  Bagged peaks: 0x{}", hex::encode(bagged))?;
        }
        writeln!(f, "  Root: 0x{}", hex::encode(self.get_root()))?;
        write!(f, "}}")
    }
}

pub fn hash_nodes<H: Hasher>(left: &[u8], right: &[u8]) -> Digest {
    let mut combined = Vec::new();
    combined.extend_from_slice(left);
    combined.extend_from_slice(right);
    H::hash(&combined)
}

pub fn get_root<H: Hasher>(leaf_count: u32, bagged_peak: &Digest) -> Digest {
    // pad leaf_count to 32 bytes left (to match solidity impl)
    let mut leaf_count_bytes = [0u8; 32];
    leaf_count_bytes[28..].copy_from_slice(&leaf_count.to_be_bytes());

    hash_nodes::<H>(&leaf_count_bytes, bagged_peak.as_ref())
}

pub fn bag_peaks<H: Hasher>(peaks: &[Digest]) -> Option<Digest> {
    peaks.iter().rev().fold(None, |acc, peak| match acc {
        None => Some(*peak),
        Some(prev) => Some(hash_nodes::<H>(peak.as_ref(), prev.as_ref())),
    })
}

pub type CompactMerkleMountainRange<H> = MerkleMountainRange<H, CompactMMR>;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct MMRProof {
    pub leaf_hash: Digest,
    pub leaf_index: u32,
    pub siblings: Vec<Digest>,
    pub peaks: Vec<Digest>,
    pub leaf_count: u32,
}

impl fmt::Debug for MMRProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MMRProof")
            .field("leaf_hash", &hex::encode(self.leaf_hash))
            .field("leaf_index", &self.leaf_index)
            .field(
                "siblings",
                &self.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
            )
            .field(
                "peaks",
                &self.peaks.iter().map(hex::encode).collect::<Vec<_>>(),
            )
            .field("leaf_count", &self.leaf_count)
            .finish()
    }
}

/// Verify a proof for a leaf in the MMR
pub fn verify_mmr_proof<H: Hasher>(root: &Digest, proof: &MMRProof) -> bool {
    // First verify the proof up to a peak
    let mut current_hash = proof.leaf_hash;

    let mut leaf_index = proof.leaf_index;
    // Apply each proof element to get to a peak
    for sibling in &proof.siblings {
        let is_right = leaf_index % 2 == 1;
        leaf_index /= 2;
        current_hash = if is_right {
            hash_nodes::<H>(sibling.as_ref(), current_hash.as_ref())
        } else {
            hash_nodes::<H>(current_hash.as_ref(), sibling.as_ref())
        };
    }

    // Verify the computed peak exists in peaks array
    if !proof.peaks.contains(&current_hash) {
        return false;
    }

    // Verify the peaks produce the expected root
    let bagged_peaks = bag_peaks::<H>(&proof.peaks).unwrap();

    let computed_root = get_root::<H>(proof.leaf_count, &bagged_peaks);
    computed_root == *root
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::hasher::Keccak256Hasher;
    use accumulators::mmr::{
        element_index_to_leaf_index, elements_count_to_leaf_count, Proof as ClientMMRProof,
    };
    use accumulators::{
        hasher::keccak::KeccakHasher as ClientKeccakHasher, mmr::MMR as ClientMMR,
        store::memory::InMemoryStore,
    };
    use hex_literal::hex;
    use std::sync::Arc;

    pub fn digest_to_hex(digest: &Digest) -> String {
        format!("0x{}", hex::encode(digest))
    }

    pub fn client_mmr_proof_to_circuit_mmr_proof(proof: &ClientMMRProof) -> MMRProof {
        println!("Proof: {:?}", proof);
        MMRProof {
            siblings: proof
                .siblings_hashes
                .iter()
                .map(|s| {
                    hex::decode(s.trim_start_matches("0x"))
                        .unwrap()
                        .try_into()
                        .unwrap()
                })
                .collect(),
            leaf_hash: hex::decode(proof.element_hash.clone().trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
            peaks: proof
                .peaks_hashes
                .iter()
                .map(|s| {
                    hex::decode(s.trim_start_matches("0x"))
                        .unwrap()
                        .try_into()
                        .unwrap()
                })
                .collect(),
            leaf_count: elements_count_to_leaf_count(proof.elements_count).unwrap() as u32,
            leaf_index: element_index_to_leaf_index(proof.element_index).unwrap() as u32,
        }
    }

    pub fn create_keccak256_client_mmr() -> ClientMMR {
        let store = InMemoryStore::default();
        let store_rc = Arc::new(store);
        let hasher = Arc::new(ClientKeccakHasher::new());
        ClientMMR::new(store_rc, hasher, None)
    }

    #[test]
    fn test_new_mmr() {
        let mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();
        assert_eq!(mmr.leaf_count, 0);
        assert!(mmr.peaks.is_empty());
    }

    #[test]
    fn test_bag_peaks() {
        let mut mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();
        mmr.append(&Digest::from([1u8; 32]));
        assert_eq!(mmr.leaf_count, 1);
        assert_eq!(mmr.peaks.len(), 1);
        assert_eq!(
            mmr.bag_peaks().unwrap(),
            hex!("0101010101010101010101010101010101010101010101010101010101010101")
        );

        let mut mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();
        mmr.append(&Digest::from([1u8; 32]));
        mmr.append(&Digest::from([2u8; 32]));
        assert_eq!(mmr.leaf_count, 2);
        assert_eq!(mmr.peaks.len(), 1);
        assert_eq!(
            mmr.bag_peaks().unwrap(),
            hex!("346d8c96a2454213fcc0daff3c96ad0398148181b9fa6488f7ae2c0af5b20aa0")
        );

        let mut mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();
        mmr.append(&Digest::from([1u8; 32]));
        mmr.append(&Digest::from([2u8; 32]));
        mmr.append(&Digest::from([3u8; 32]));
        assert_eq!(mmr.leaf_count, 3);
        assert_eq!(mmr.peaks.len(), 2);
        assert_eq!(
            mmr.bag_peaks().unwrap(),
            hex!("f8f23a80fd4d99d9d231122e1f115145412be3856b23abcc338903e32a80c4ef")
        );
    }

    #[tokio::test]
    async fn test_simple_proof_verification() {
        let mut client_mmr = create_keccak256_client_mmr();

        let leaves = [
            Digest::from([1u8; 32]),
            Digest::from([2u8; 32]),
            Digest::from([3u8; 32]),
        ];

        let mut indices = Vec::new();

        for leaf in &leaves {
            println!("Appending leaf: {}", digest_to_hex(leaf));
            let index = client_mmr.append(digest_to_hex(leaf)).await.unwrap();
            println!("Index: {}", index.element_index);
            indices.push(index.element_index);
        }

        for index in indices {
            println!("Getting proof for index: {}", index);
            let proof = client_mmr.get_proof(index, None).await.unwrap();

            let minimal_proof = client_mmr_proof_to_circuit_mmr_proof(&proof);
            println!("Minimal proof: {:?}", minimal_proof);

            // Now instantiate the proof MMR and then verify a proof based on that
            let circuit_mmr = CompactMerkleMountainRange::<Keccak256Hasher>::from_peaks(
                &minimal_proof.peaks,
                minimal_proof.leaf_count,
            );

            assert!(verify_mmr_proof::<Keccak256Hasher>(
                &circuit_mmr.get_root(),
                &minimal_proof
            ));
            println!("Proof verified");
        }
    }

    #[tokio::test]
    async fn test_proof_verification_single_leaf() {
        let mut client_mmr = create_keccak256_client_mmr();

        // Test with single leaf
        let leaf = Digest::from([1u8; 32]);
        let index = client_mmr.append(digest_to_hex(&leaf)).await.unwrap();
        let proof = client_mmr
            .get_proof(index.element_index, None)
            .await
            .unwrap();
        let minimal_proof = client_mmr_proof_to_circuit_mmr_proof(&proof);

        println!("Single leaf proof: {:?}", minimal_proof);

        let circuit_mmr = CompactMerkleMountainRange::<Keccak256Hasher>::from_peaks(
            &minimal_proof.peaks,
            minimal_proof.leaf_count,
        );

        assert!(verify_mmr_proof::<Keccak256Hasher>(
            &circuit_mmr.get_root(),
            &minimal_proof
        ));
    }

    #[tokio::test]
    async fn test_proof_verification_power_of_two() {
        let mut client_mmr = create_keccak256_client_mmr();

        // Test with 4 leaves (power of 2)
        let leaves: Vec<Digest> = (0..4).map(|i| Digest::from([i as u8; 32])).collect();
        let mut indices = Vec::new();

        for leaf in &leaves {
            let index = client_mmr.append(digest_to_hex(leaf)).await.unwrap();
            indices.push(index.element_index);
        }

        // Verify proof for each leaf
        for &idx in &indices {
            let proof = client_mmr.get_proof(idx, None).await.unwrap();
            let minimal_proof = client_mmr_proof_to_circuit_mmr_proof(&proof);

            println!("Minimal proof: {:?}", minimal_proof);

            let circuit_mmr = CompactMerkleMountainRange::<Keccak256Hasher>::from_peaks(
                &minimal_proof.peaks,
                minimal_proof.leaf_count,
            );

            assert!(verify_mmr_proof::<Keccak256Hasher>(
                &circuit_mmr.get_root(),
                &minimal_proof
            ));
            println!("Proof verified for pow of two");
        }
    }

    #[tokio::test]
    async fn test_proof_verification_large_tree() {
        let mut client_mmr = create_keccak256_client_mmr();

        // Test with 1000 leaves (creates multiple peaks)
        let leaves: Vec<Digest> = (0..1000_u32)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[28..32].copy_from_slice(&i.to_be_bytes());
                bytes[0] = (i >> 24) as u8;
                bytes[16] = (i >> 16) as u8;
                Digest::from(bytes)
            })
            .collect();
        let mut indices = Vec::new();

        for leaf in &leaves {
            let index = client_mmr.append(digest_to_hex(leaf)).await.unwrap();
            indices.push(index.element_index);
        }

        // Verify first, middle, and last leaf
        for &idx in [indices[0], indices[500], indices[999]].iter() {
            let proof = client_mmr.get_proof(idx, None).await.unwrap();
            let minimal_proof = client_mmr_proof_to_circuit_mmr_proof(&proof);

            let circuit_mmr = CompactMerkleMountainRange::<Keccak256Hasher>::from_peaks(
                &minimal_proof.peaks,
                minimal_proof.leaf_count,
            );

            assert!(verify_mmr_proof::<Keccak256Hasher>(
                &circuit_mmr.get_root(),
                &minimal_proof
            ));
        }
    }

    #[test]
    #[should_panic(expected = "Invalid peak count")]
    fn test_invalid_peak_count() {
        // Try to create MMR with incorrect number of peaks
        let peaks = vec![Digest::from([1u8; 32])];
        CompactMerkleMountainRange::<Keccak256Hasher>::from_peaks(&peaks, 3); // 3 leaves should have 2 peaks
    }

    #[test]
    fn test_validate_mmr_transition() {
        let mut initial_mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();

        // Add initial leaves
        let initial_leaves = [Digest::from([1u8; 32]), Digest::from([2u8; 32])];
        for leaf in &initial_leaves {
            initial_mmr.append(leaf);
        }

        // Create new leaves to validate transition
        let new_leaves = [Digest::from([3u8; 32]), Digest::from([4u8; 32])];

        // Create expected final state to get root
        let mut expected_final_mmr = initial_mmr.clone();
        for leaf in &new_leaves {
            expected_final_mmr.append(leaf);
        }
        let expected_root = expected_final_mmr.get_root();

        // Validate the transition
        initial_mmr.validate_mmr_transition(&new_leaves, &expected_root);
    }

    #[test]
    #[should_panic(expected = "Invalid MMR: root mismatch")]
    fn test_validate_mmr_transition_invalid() {
        let mut initial_mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();

        // Add initial leaves
        let initial_leaves = [Digest::from([1u8; 32]), Digest::from([2u8; 32])];
        for leaf in &initial_leaves {
            initial_mmr.append(leaf);
        }

        // Create new leaves
        let new_leaves = [Digest::from([3u8; 32]), Digest::from([4u8; 32])];

        // Create an invalid expected root
        let invalid_root = Digest::from([0xff; 32]);

        // This should panic due to root mismatch
        initial_mmr.validate_mmr_transition(&new_leaves, &invalid_root);
    }

    #[tokio::test]
    async fn test_update_mmr_peaks() {
        let mut client_mmr = create_keccak256_client_mmr();
        let mut circuit_mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();

        // Create test leaves
        let leaves: Vec<Digest> = (0..1000_u32)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[28..32].copy_from_slice(&i.to_be_bytes());
                bytes[0] = (i >> 24) as u8;
                bytes[16] = (i >> 16) as u8;
                Digest::from(bytes)
            })
            .collect();

        // Add leaves one by one and compare peaks
        for leaf in &leaves {
            // Add to client MMR
            let index = client_mmr.append(digest_to_hex(leaf)).await.unwrap();
            let proof = client_mmr
                .get_proof(index.element_index, None)
                .await
                .unwrap();

            // Add to circuit MMR
            circuit_mmr.append(leaf);

            // Compare peaks
            let client_peaks: Vec<Digest> = proof
                .peaks_hashes
                .iter()
                .map(|s| {
                    hex::decode(s.trim_start_matches("0x"))
                        .unwrap()
                        .try_into()
                        .unwrap()
                })
                .collect();

            assert_eq!(
                circuit_mmr.peaks,
                client_peaks,
                "Peaks mismatch after adding leaf {}: \ncircuit peaks: {:?}\nclient peaks: {:?}",
                hex::encode(leaf),
                circuit_mmr
                    .peaks
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
                client_peaks.iter().map(hex::encode).collect::<Vec<_>>()
            );

            println!(
                "Peaks match after adding leaf {}. Peaks: {:?}",
                hex::encode(leaf),
                circuit_mmr
                    .peaks
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>()
            );
        }
    }
}
