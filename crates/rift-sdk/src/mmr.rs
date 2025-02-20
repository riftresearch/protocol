// TODO: low priority, make IndexedMMR clonable so that we can clone a built BchOverwriteMMRState instead of having to re-build it
// for each swap (or maybe just rewind it???)
use std::convert::TryInto;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

use alloy::hex;
use serde::{Deserialize, Serialize};

use accumulators::mmr::{
    self, element_index_to_leaf_index, elements_count_to_leaf_count,
    map_leaf_index_to_element_index, AppendResult, PeaksOptions, Proof as ClientMMRProof,
    ProofOptions, MMR as ClientMMR,
};
use accumulators::{
    hasher::keccak::KeccakHasher as AccumulatorsKeccakHasher,
    store::{memory::InMemoryStore, sqlite::SQLiteStore, Store},
};

use bitcoin_light_client_core::hasher::{Digest as LeafDigest, Hasher as LeafHasher};
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoin_light_client_core::mmr::get_root as circuit_get_root;
use bitcoin_light_client_core::mmr::MMRProof as CircuitMMRProof;

use crate::errors::{Result, RiftSdkError};
use crate::DatabaseLocation;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Convert a 32-byte `LeafDigest` to a "0x"-prefixed hex string.
pub fn digest_to_hex(digest: &LeafDigest) -> String {
    format!("0x{}", hex::encode(digest))
}

/// Convert a `BlockLeaf` to a hex representation.
pub fn leaf_to_hex(leaf: &BlockLeaf) -> String {
    let serialized = leaf.serialize();
    format!("0x{}", hex::encode(serialized))
}

/// Convert a hex string (like "0xabc123...") back into a `BlockLeaf`.
/// If `BlockLeaf::deserialize` returns the `BlockLeaf` directly, we just do so here.
/// If it returned a `Result`, we would chain `.map_err`.
pub fn hex_to_leaf(hex_str: &str) -> Result<BlockLeaf> {
    let without_prefix = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(without_prefix)
        .map_err(|e| RiftSdkError::MMRError(format!("Failed to decode leaf hex: {e}")))?;
    // If BlockLeaf::deserialize returns a BlockLeaf directly:
    Ok(BlockLeaf::deserialize(&bytes))
}

/// Convert a rust-accumulators `ClientMMRProof` into the circuit's `CircuitMMRProof`.
/// (If you don't need this, you can remove it.)
pub fn client_mmr_proof_to_circuit_mmr_proof(proof: &ClientMMRProof) -> Result<CircuitMMRProof> {
    // Convert siblings
    let siblings = proof
        .siblings_hashes
        .iter()
        .map(|h| {
            let stripped = h.trim_start_matches("0x");
            let bytes = hex::decode(stripped)
                .map_err(|e| RiftSdkError::MMRError(format!("Hex decode error: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| RiftSdkError::MMRError("siblings hash size mismatch".to_string()))?;
            Ok(arr)
        })
        .collect::<Result<Vec<[u8; 32]>>>()?;

    // Convert peaks
    let peaks = proof
        .peaks_hashes
        .iter()
        .map(|p| {
            let stripped = p.trim_start_matches("0x");
            let bytes = hex::decode(stripped)
                .map_err(|e| RiftSdkError::MMRError(format!("Hex decode error: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| RiftSdkError::MMRError("peaks hash size mismatch".to_string()))?;
            Ok(arr)
        })
        .collect::<Result<Vec<[u8; 32]>>>()?;

    // Convert element_hash
    let stripped = proof.element_hash.trim_start_matches("0x");
    let elem_bytes = hex::decode(stripped)
        .map_err(|e| RiftSdkError::MMRError(format!("Hex decode error: {e}")))?;
    let elem_arr: [u8; 32] = elem_bytes
        .try_into()
        .map_err(|_| RiftSdkError::MMRError("element hash size mismatch".to_string()))?;

    // Convert leaf_count, leaf_index
    let leaf_count_u64 = elements_count_to_leaf_count(proof.elements_count)
        .map_err(|e| RiftSdkError::MMRError(format!("Bad elements_count: {e}")))?;
    let leaf_index_u64 = element_index_to_leaf_index(proof.element_index)
        .map_err(|e| RiftSdkError::MMRError(format!("Bad element_index: {e}")))?;

    Ok(CircuitMMRProof {
        siblings,
        leaf_hash: elem_arr,
        peaks,
        leaf_count: leaf_count_u64 as u32,
        leaf_index: leaf_index_u64 as u32,
    })
}

/// Compute MMR root (32 bytes) using a *bitcoin_light_client_core* hasher `LeafHasher`.
/// The accumulators MMR bagged-peaks are hashed again with Circuit's `get_root`.
pub async fn client_mmr_to_root<H: LeafHasher>(client_mmr: &ClientMMR) -> Result<LeafDigest> {
    let leaves_count = client_mmr
        .leaves_count
        .get()
        .await
        .map_err(|e| RiftSdkError::MMRError(format!("Failed to get leaves_count: {e}")))?;

    if leaves_count == 0 {
        return Err(RiftSdkError::MMRError("No leaves in the MMR".to_string()));
    }

    let bagged_peaks = bag_peaks::<H>(client_mmr).await?;

    // use Circuit's get_root function
    Ok(circuit_get_root::<H>(leaves_count as u32, &bagged_peaks))
}

pub async fn bag_peaks<H: LeafHasher>(client_mmr: &ClientMMR) -> Result<LeafDigest> {
    let bagged_peaks_hex = client_mmr
        .bag_the_peaks(None)
        .await
        .map_err(|e| RiftSdkError::MMRError(format!("Failed to bag the peaks: {e}")))?;

    // bagged_peaks_hex is "0x..." => strip it
    let bagged_peaks_str = bagged_peaks_hex.trim_start_matches("0x");
    let bagged_peaks_bytes = hex::decode(bagged_peaks_str)
        .map_err(|e| RiftSdkError::MMRError(format!("Hex decode error: {e}")))?;
    let bagged_peaks_32: [u8; 32] = bagged_peaks_bytes
        .try_into()
        .map_err(|_| RiftSdkError::MMRError("Bagged peaks not 32 bytes".to_string()))?;

    Ok(bagged_peaks_32)
}

// -----------------------------------------------------------------------------
// ReverseIndex: a separate key prefix "revIndex:..." for (leaf_hash -> { index, data })
// -----------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReverseIndexValue {
    element_index: usize,
    leaf_data: BlockLeaf,
}

#[derive(Debug)]
struct ReverseIndex {
    store: Arc<dyn Store + Send + Sync>,
    key_prefix: String,
}

impl ReverseIndex {
    fn new(store: Arc<dyn Store + Send + Sync>, key_prefix: &str) -> Self {
        Self {
            store,
            key_prefix: key_prefix.to_string(),
        }
    }

    fn make_key(&self, leaf_hash_hex: &str) -> String {
        format!("{}{}", self.key_prefix, leaf_hash_hex)
    }

    async fn insert(
        &self,
        leaf_hash: &LeafDigest,
        element_index: usize,
        leaf_data: &BlockLeaf,
    ) -> Result<()> {
        let leaf_hash_hex = digest_to_hex(leaf_hash);
        let key = self.make_key(&leaf_hash_hex);

        let val_obj = ReverseIndexValue {
            element_index,
            leaf_data: *leaf_data,
        };
        let serialized = serde_json::to_string(&val_obj)
            .map_err(|e| RiftSdkError::StoreError(format!("Serialize error: {e}")))?;

        self.store
            .set(&key, &serialized)
            .await
            .map_err(|e| RiftSdkError::StoreError(format!("Store set error: {e}")))?;
        Ok(())
    }

    async fn get_by_hash(&self, leaf_digest: &LeafDigest) -> Result<Option<ReverseIndexValue>> {
        let leaf_hash_hex = digest_to_hex(leaf_digest);
        let key = self.make_key(&leaf_hash_hex);

        let val_opt = self
            .store
            .get(&key)
            .await
            .map_err(|e| RiftSdkError::StoreError(format!("Store get error: {e}")))?;

        if let Some(serialized) = val_opt {
            let parsed: ReverseIndexValue = serde_json::from_str(&serialized)
                .map_err(|e| RiftSdkError::StoreError(format!("Deserialize error: {e}")))?;
            Ok(Some(parsed))
        } else {
            Ok(None)
        }
    }

    async fn delete_many(&self, leaf_hashes_hex: Vec<String>) -> Result<()> {
        let keys: Vec<String> = leaf_hashes_hex
            .into_iter()
            .map(|hash_hex| self.make_key(&hash_hex))
            .collect();

        let key_refs: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();

        self.store
            .delete_many(key_refs)
            .await
            .map_err(|e| RiftSdkError::StoreError(format!("Store delete_many error: {e}")))?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// IndexedMMR: wrap the accumulators MMR + a ReverseIndex; generic over "leaf hasher" H
// -----------------------------------------------------------------------------
#[derive(Debug)]
pub struct IndexedMMR<H: LeafHasher> {
    client_mmr: ClientMMR,                 // uses Keccak internally for MMR ops
    reverse_index: ReverseIndex,           // separate prefix
    _phantom: std::marker::PhantomData<H>, // we never store H itself, only use it generically
}

impl<H: LeafHasher> IndexedMMR<H> {
    /// Single constructor: open or create the store, check or set hasherType, build the MMR + ReverseIndex.
    /// For simplicity, we store a string like "myLeafHasher" under "hasherType" in the DB.
    pub async fn open(database_location: DatabaseLocation) -> Result<Self> {
        let hasher_name = H::name();
        // TODO: Unified hasher for circuit and client. For now: generic circuit hasher must be keccak256 to match the client
        assert_eq!(hasher_name, "keccak256");
        // 1) Create the underlying store
        let store: Arc<dyn Store + Send + Sync> = match database_location {
            DatabaseLocation::InMemory => Arc::new(InMemoryStore::default()),
            DatabaseLocation::Directory(path) => {
                let mmr_db_path = PathBuf::from(path).join("mmr.db");
                let mmr_db_path_str = mmr_db_path.to_str().expect("Invalid path");
                let sqlite = SQLiteStore::new(mmr_db_path_str, Some(true), None)
                    .await
                    .map_err(|e| RiftSdkError::StoreError(e.to_string()))?;
                Arc::new(sqlite)
            }
        };

        // 2) Check or set the hasherType key
        match store.get("hasherType").await {
            Ok(Some(existing)) => {
                if existing != hasher_name {
                    return Err(RiftSdkError::MMRError(format!(
                        "DB hasherType is '{existing}', but requested '{hasher_name}'"
                    )));
                }
            }
            Ok(None) => {
                // set it
                store
                    .set("hasherType", hasher_name)
                    .await
                    .map_err(|e| RiftSdkError::StoreError(format!("Store set error: {e}")))?;
            }
            Err(e) => {
                return Err(RiftSdkError::StoreError(format!(
                    "Failed to read 'hasherType': {e}"
                )));
            }
        }

        // 3) Create the accumulators MMR with Arc<KeccakHasher> (example).
        //    (We do NOT use H for the accumulators MMR, because H is for leaf hashing in Circuit.)
        let mmr_hasher = Arc::new(AccumulatorsKeccakHasher::new());
        let client_mmr = ClientMMR::new(store.clone(), mmr_hasher, Some("mmr".to_string()));

        // 4) Build the reverse index
        let reverse_index = ReverseIndex::new(store.clone(), "revIndex:");

        Ok(Self {
            client_mmr,
            reverse_index,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Append or reorg based on a "parent" leaf; the first leaf in `leaves` is the parent.
    /// If it exists in the MMR, we rewind to it and append the rest; else we fail.
    pub async fn append_or_reorg_based_on_parent(&mut self, leaves: &[BlockLeaf]) -> Result<()> {
        if leaves.is_empty() {
            return Err(RiftSdkError::MMRError("No leaves provided".into()));
        }
        let parent = &leaves[0];
        let parent_hash = parent.hash::<H>();

        println!("[in append_or_reorg_based_on_parent] leaves: {:?}", leaves);
        println!(
            "[in append_or_reorg_based_on_parent] parent_hash: {:?}",
            hex::encode(parent_hash)
        );

        let new_leaves = &leaves[1..];

        match self.get_leaf_by_leaf_hash(&parent_hash).await? {
            Some((element_index, _)) => {
                let leaf_index = element_index_to_leaf_index(element_index)
                    .map_err(|e| RiftSdkError::MMRError(format!("Failed leaf_index: {e}")))?;
                self.rewind(leaf_index).await?;
                self.batch_append(new_leaves).await?;
                Ok(())
            }
            None => Err(RiftSdkError::MMRError(
                "Parent leaf not found in the MMR".to_string(),
            )),
        }
    }

    /// Rewind to a given leaf index, removing subsequent leaves.
    pub async fn rewind(&mut self, parent_leaf_index: usize) -> Result<()> {
        let pruned_leaf_hashes = self
            .client_mmr
            .rewind(parent_leaf_index)
            .await
            .map_err(|e| RiftSdkError::MMRError(format!("Failed to rewind: {e}")))?;

        self.reverse_index.delete_many(pruned_leaf_hashes).await?;
        Ok(())
    }

    /// Batch append leaves, storing them in the accumulators MMR and the reverse index.
    pub async fn batch_append(&mut self, leaves: &[BlockLeaf]) -> Result<Vec<AppendResult>> {
        let mut append_results = Vec::new();
        for leaf in leaves {
            let leaf_hash = leaf.hash::<H>();
            let leaf_hash_hex = digest_to_hex(&leaf_hash);

            let append_res = self
                .client_mmr
                .append(leaf_hash_hex)
                .await
                .map_err(|e| RiftSdkError::AppendLeafError(e.to_string()))?;

            self.reverse_index
                .insert(&leaf_hash, append_res.element_index, leaf)
                .await?;
            append_results.push(append_res);
        }
        Ok(append_results)
    }

    /// Append a single leaf to the MMR and the reverse index.
    pub async fn append(&mut self, leaf: &BlockLeaf) -> Result<AppendResult> {
        self.batch_append(&[*leaf])
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| RiftSdkError::MMRError("Empty append result".into()))
    }

    pub async fn get_client_proof(
        &self,
        leaf_index: usize,
        elements_count: Option<usize>,
    ) -> Result<ClientMMRProof> {
        self.client_mmr
            .get_proof(
                map_leaf_index_to_element_index(leaf_index),
                Some(ProofOptions {
                    elements_count,
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| RiftSdkError::MMRError(format!("Failed to get proof: {e}")))
    }

    pub async fn get_circuit_proof(
        &self,
        leaf_index: usize,
        elements_count: Option<usize>,
    ) -> Result<CircuitMMRProof> {
        client_mmr_proof_to_circuit_mmr_proof(
            &self.get_client_proof(leaf_index, elements_count).await?,
        )
    }

    /// Get the MMR root as a 32-byte `LeafDigest`, using Circuit's `get_root`.
    pub async fn get_root(&self) -> Result<LeafDigest> {
        client_mmr_to_root::<H>(&self.client_mmr).await
    }

    /// Find if a given leaf-hash is in our reverse index => returns (index, data).
    pub async fn get_leaf_by_leaf_hash(
        &self,
        leaf_hash: &LeafDigest,
    ) -> Result<Option<(usize, BlockLeaf)>> {
        let val_opt = self.reverse_index.get_by_hash(leaf_hash).await?;
        Ok(val_opt.map(|v| (v.element_index, v.leaf_data)))
    }

    pub async fn get_leaf_by_leaf_index(&self, leaf_index: usize) -> Result<Option<BlockLeaf>> {
        // Get the hash at the leaf index
        let hash_opt = self
            .client_mmr
            .hashes
            .get(accumulators::store::SubKey::Usize(
                map_leaf_index_to_element_index(leaf_index),
            ))
            .await
            .map_err(|e| RiftSdkError::MMRError(format!("Failed to get leaf: {e}")))?;

        // If no hash found at this index, return None
        let hash_str = match hash_opt {
            Some(h) => h,
            None => return Ok(None),
        };

        // Convert the hex hash to LeafDigest
        let leaf_hash =
            LeafDigest::from(
                <[u8; 32]>::try_from(hex::decode(hash_str.trim_start_matches("0x")).map_err(
                    |e| RiftSdkError::MMRError(format!("Failed to decode leaf hash: {e}")),
                )?)
                .map_err(|_| RiftSdkError::MMRError("Invalid hash length".to_string()))?,
            );

        // Look up the leaf data in the reverse index
        // if it doesn't exist here, something is wrong so error out
        let reverse_index = match self.reverse_index.get_by_hash(&leaf_hash).await? {
            Some(data) => data,
            None => {
                return Err(RiftSdkError::MMRError(
                    "Leaf not found in reverse index".to_string(),
                ))
            }
        };

        Ok(Some(reverse_index.leaf_data))
    }

    /// Return the internal accumulators MMR if needed.
    pub fn client_mmr(&self) -> &ClientMMR {
        &self.client_mmr
    }

    /// Return the name of the leaf hasher (whatever we stored under "hasherType").
    pub fn leaf_hasher_name(&self) -> &str {
        H::name()
    }

    pub async fn get_leaf_count(&self) -> Result<usize> {
        self.client_mmr
            .leaves_count
            .get()
            .await
            .map_err(|e| RiftSdkError::MMRError(format!("Failed to get leaf count: {e}")))
    }

    pub async fn get_peaks(&self, elements_count: Option<usize>) -> Result<Vec<LeafDigest>> {
        self.client_mmr
            .get_peaks(PeaksOptions {
                elements_count,
                formatting_opts: None,
            })
            .await
            .map_err(|e| RiftSdkError::MMRError(format!("Failed to get peaks: {e}")))?
            .iter()
            .map(|p| {
                let stripped = p.trim_start_matches("0x");
                let bytes = hex::decode(stripped)
                    .map_err(|e| RiftSdkError::MMRError(format!("Hex decode error: {e}")))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| RiftSdkError::MMRError("peaks hash size mismatch".to_string()))?;
                Ok(arr)
            })
            .collect::<Result<Vec<[u8; 32]>>>()
    }

    pub async fn get_bagged_peak(&self) -> Result<LeafDigest> {
        bag_peaks::<H>(&self.client_mmr).await
    }
}

// -----------------------------------------------------------------------------
// Example tests (the same style you had), adapted to call `IndexedMMR::open`
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_light_client_core::hasher::Digest;
    use bitcoin_light_client_core::hasher::Keccak256Hasher;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_in_memory_open() -> Result<()> {
        // 1) Create or open the MMR
        let mut mmr = IndexedMMR::<Keccak256Hasher>::open(DatabaseLocation::InMemory).await?;

        // 2) Append a leaf
        let leaf = BlockLeaf {
            block_hash: [1u8; 32],
            cumulative_chainwork: [2u8; 32],
            height: 42,
        };
        mmr.batch_append(&[leaf]).await?;

        // 3) Verify existence
        let h = leaf.hash::<Keccak256Hasher>();
        let found = mmr.get_leaf_by_leaf_hash(&h).await?;
        assert!(found.is_some(), "Leaf should be found");

        // 4) Check root is not zero
        let root = mmr.get_root().await?;
        assert_ne!(root, [0u8; 32]);

        // 5) Confirm hasher name
        assert_eq!(mmr.leaf_hasher_name(), "keccak256");
        Ok(())
    }

    #[tokio::test]
    async fn test_sqlite_open_and_hasher_check() -> Result<()> {
        let tmp = tempdir().unwrap();
        let tmp_path_str = tmp.path().to_str().unwrap().to_string();
        let database_location = DatabaseLocation::Directory(tmp_path_str);

        // 1) First open => sets hasherType
        {
            let mut mmr = IndexedMMR::<Keccak256Hasher>::open(database_location.clone()).await?;

            // append a leaf
            let leaf = BlockLeaf {
                block_hash: [0xAA; 32],
                cumulative_chainwork: [0xBB; 32],
                height: 100,
            };
            mmr.batch_append(&[leaf]).await?;
        }

        // 2) Second open => same hasherType => OK
        {
            let mmr2 = IndexedMMR::<Keccak256Hasher>::open(database_location.clone()).await?;
            assert_eq!(mmr2.leaf_hasher_name(), "keccak256");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_indexed_mmr_creation() -> Result<()> {
        let mut indexed_mmr =
            IndexedMMR::<Keccak256Hasher>::open(DatabaseLocation::InMemory).await?;

        // Optional: Add some test data
        let test_leaf = BlockLeaf {
            block_hash: [12u8; 32],
            cumulative_chainwork: [1u8; 32],
            height: 1,
        };

        // Append the leaf and verify it was stored
        indexed_mmr.batch_append(&[test_leaf]).await?;

        // Verify the leaf can be found
        let leaf_hash = test_leaf.hash::<Keccak256Hasher>();
        let found = indexed_mmr.get_leaf_by_leaf_hash(&leaf_hash).await?;
        assert!(found.is_some());

        // try to find a leaf that doesn't exist
        let test_leaf = BlockLeaf {
            block_hash: [13u8; 32],
            cumulative_chainwork: [1u8; 32],
            height: 2,
        };

        let leaf_hash = test_leaf.hash::<Keccak256Hasher>();
        let found = indexed_mmr.get_leaf_by_leaf_hash(&leaf_hash).await?;
        assert!(found.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_sqlite_persistence() -> Result<()> {
        use tempfile::tempdir;

        // Create a temporary directory that will be automatically cleaned up
        let temp_dir = tempdir().unwrap();
        let temp_dir_path_str = temp_dir.path().to_str().unwrap().to_string();
        let mmr_db_location = DatabaseLocation::Directory(temp_dir_path_str);

        // Test data
        let test_leaf = BlockLeaf {
            block_hash: [42u8; 32],
            cumulative_chainwork: [1u8; 32],
            height: 100,
        };
        let leaf_hash = test_leaf.hash::<Keccak256Hasher>();

        let original_root: Digest;

        // First instance: Create and populate the MMR
        {
            let mut indexed_mmr =
                IndexedMMR::<Keccak256Hasher>::open(mmr_db_location.clone()).await?;
            indexed_mmr.batch_append(&[test_leaf]).await?;

            // validate the underyling mmr client has leaf count > 0
            let leaves = indexed_mmr.client_mmr.leaves_count.get().await.unwrap();
            assert!(leaves > 0);

            // Get the root before dropping
            original_root = indexed_mmr.get_root().await?;

            // Let indexed_mmr go out of scope here
        }

        // Second instance: Create new MMR with same database path
        {
            let indexed_mmr = IndexedMMR::<Keccak256Hasher>::open(mmr_db_location.clone()).await?;

            // Verify we can find the leaf
            let found = indexed_mmr.get_leaf_by_leaf_hash(&leaf_hash).await?;
            assert!(found.is_some());
            println!("found: {:?}", found);

            let (_, found_leaf) = found.unwrap();
            assert_eq!(found_leaf.height, test_leaf.height);
            assert_eq!(found_leaf.block_hash, test_leaf.block_hash);
            assert_eq!(
                found_leaf.cumulative_chainwork,
                test_leaf.cumulative_chainwork
            );

            // verify the loaded client mmr has leaves
            let leaves = indexed_mmr.client_mmr.leaves_count.get().await.unwrap();
            println!("leaves: {}", leaves);
            assert!(leaves > 0);

            // Verify the root is the same
            let loaded_root = indexed_mmr.get_root().await?;
            assert_eq!(loaded_root, original_root);
        }

        // Clean up by removing the temporary directory and all its contents
        temp_dir.close().unwrap();

        Ok(())
    }

    #[tokio::test]
    async fn test_append_or_reorg_based_on_parent() -> Result<()> {
        let mmr_db_location = DatabaseLocation::InMemory;
        let mut indexed_mmr = IndexedMMR::<Keccak256Hasher>::open(mmr_db_location).await?;

        // 2) Insert three leaves: A, B, C
        //    For a "realistic" scenario, we vary the block_hash & height
        let leaf_a = BlockLeaf {
            block_hash: [0xAA; 32],
            cumulative_chainwork: [0x11; 32],
            height: 100,
        };
        let leaf_b = BlockLeaf {
            block_hash: [0xBB; 32],
            cumulative_chainwork: [0x22; 32],
            height: 101,
        };
        let leaf_c = BlockLeaf {
            block_hash: [0xCC; 32],
            cumulative_chainwork: [0x33; 32],
            height: 102,
        };
        let initial_leaves = vec![leaf_a, leaf_b, leaf_c];
        for leaf in initial_leaves.iter() {
            println!(
                "[INITIAL] appending leaf: {}",
                digest_to_hex(&leaf.hash::<Keccak256Hasher>())
            );
        }
        indexed_mmr.batch_append(&initial_leaves).await?;

        // 3) Confirm we have 3 leaves in the MMR
        let leaves_count = indexed_mmr
            .client_mmr()
            .leaves_count
            .get()
            .await
            .expect("Failed to get leaves_count");
        assert_eq!(leaves_count, 3);

        // 4) Let's create two new leaves X, Y and pass them in array [B, X, Y] => B is the parent
        let leaf_x = BlockLeaf {
            block_hash: [0x99; 32],
            cumulative_chainwork: [0x44; 32],
            height: 103,
        };
        let leaf_y = BlockLeaf {
            block_hash: [0xEE; 32],
            cumulative_chainwork: [0x55; 32],
            height: 104,
        };

        // 5) Because B is in the MMR, we expect to reorg back to B's index (removing C) and then append X and Y
        let leaves_to_add = [leaf_b, leaf_x, leaf_y];
        indexed_mmr
            .append_or_reorg_based_on_parent(&leaves_to_add)
            .await
            .expect("append_or_reorg_based_on_parent should succeed");

        // 6) Confirm final MMR leaves = A, B, X, Y
        //    - We'll just check that C is gone, X and Y are present, total leaf_count == 4
        let leaves_count = indexed_mmr
            .client_mmr()
            .leaves_count
            .get()
            .await
            .expect("Failed to get leaves_count post-reorg");

        assert_eq!(leaves_count, 4, "C was removed, X and Y were appended");

        // 7) Check that new leaves are indeed found in the reverse index
        let x_found = indexed_mmr
            .get_leaf_by_leaf_hash(&leaf_x.hash::<Keccak256Hasher>())
            .await?;
        let y_found = indexed_mmr
            .get_leaf_by_leaf_hash(&leaf_y.hash::<Keccak256Hasher>())
            .await?;
        assert!(x_found.is_some(), "Leaf X should be present");
        assert!(y_found.is_some(), "Leaf Y should be present");

        // Confirm that C is no longer found
        let c_found = indexed_mmr
            .get_leaf_by_leaf_hash(&leaf_c.hash::<Keccak256Hasher>())
            .await?;
        println!("c_found: {:?}", c_found);
        assert!(c_found.is_none(), "Leaf C should have been pruned");

        // 8) Now test the error path: pass a "fake parent" leaf not in the MMR
        let fake_leaf = BlockLeaf {
            block_hash: [0xDD; 32],
            cumulative_chainwork: [0x66; 32],
            height: 9999,
        };
        let new_leaf = BlockLeaf {
            block_hash: [0x77; 32],
            cumulative_chainwork: [0x77; 32],
            height: 1000,
        };
        let reorg_result = indexed_mmr
            .append_or_reorg_based_on_parent(&[fake_leaf, new_leaf])
            .await;
        assert!(
            reorg_result.is_err(),
            "Should fail because the parent (fake_leaf) wasn't in the MMR"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_append_or_reorg_based_on_parent_no_reorg() -> Result<()> {
        // 1) Create an in-memory IndexedMMR
        let mmr_db_location = DatabaseLocation::InMemory;
        let mut indexed_mmr = IndexedMMR::<Keccak256Hasher>::open(mmr_db_location).await?;

        // 2) Insert initial leaves A and B
        let leaf_a = BlockLeaf {
            block_hash: [0xAA; 32],
            cumulative_chainwork: [0x11; 32],
            height: 100,
        };
        let leaf_b = BlockLeaf {
            block_hash: [0xBB; 32],
            cumulative_chainwork: [0x22; 32],
            height: 101,
        };
        let initial_leaves = vec![leaf_a, leaf_b];
        indexed_mmr.batch_append(&initial_leaves).await?;

        // 3) Create new leaves C and D to append after B (the current tip)
        let leaf_c = BlockLeaf {
            block_hash: [0xCC; 32],
            cumulative_chainwork: [0x33; 32],
            height: 102,
        };
        let leaf_d = BlockLeaf {
            block_hash: [0xDD; 32],
            cumulative_chainwork: [0x44; 32],
            height: 103,
        };

        // 4) Append using B as parent (should not trigger reorg)
        let leaves_to_add = [leaf_b, leaf_c, leaf_d];
        indexed_mmr
            .append_or_reorg_based_on_parent(&leaves_to_add)
            .await?;

        // 5) Verify final state
        let leaves_count = indexed_mmr
            .client_mmr()
            .leaves_count
            .get()
            .await
            .expect("Failed to get leaves_count");

        // Should have 4 leaves total (A, B, C, D)
        assert_eq!(leaves_count, 4, "Should have all leaves present");

        // Verify all leaves are present in the correct order
        let all_leaves = [leaf_a, leaf_b, leaf_c, leaf_d];
        for leaf in all_leaves.iter() {
            let found = indexed_mmr
                .get_leaf_by_leaf_hash(&leaf.hash::<Keccak256Hasher>())
                .await?;
            assert!(found.is_some(), "Leaf should be present in MMR");
        }

        Ok(())
    }
}
