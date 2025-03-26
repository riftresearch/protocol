use std::collections::HashMap;
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
use accumulators::store::{memory::InMemoryStore, sqlite::SQLiteStore, Store};

use bitcoin_light_client_core::hasher::{Digest as LeafDigest, Hasher as LeafHasher};
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoin_light_client_core::mmr::MMRProof as CircuitMMRProof;

use crate::errors::{Result, RiftSdkError};
use crate::indexed_mmr::IndexedMMR;
use crate::DatabaseLocation;

const NULL_LEAF_HASH: LeafDigest = [0; 32];

// -----------------------------------------------------------------------------
// Checkpoint: map of (mmr_root -> tip_leaf_hash)
// -----------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Checkpoint {
    tip_leaf_hash: LeafDigest,
}

#[derive(Debug)]
struct CheckpointMap {
    store: Arc<dyn Store + Send + Sync>,
    key_prefix: String,
}

impl CheckpointMap {
    fn new(store: Arc<dyn Store + Send + Sync>, key_prefix: &str) -> Self {
        Self {
            store,
            key_prefix: key_prefix.to_string(),
        }
    }

    fn make_key(&self, mmr_root_hex: &str) -> String {
        format!("{}{}", self.key_prefix, mmr_root_hex)
    }

    async fn insert(
        &self,
        checkpoint_mmr_root: &LeafDigest,
        tip_leaf_hash: &LeafDigest,
    ) -> Result<()> {
        let key = self.make_key(&digest_to_hex(checkpoint_mmr_root));

        let val_obj = Checkpoint {
            tip_leaf_hash: *tip_leaf_hash,
        };
        let serialized = serde_json::to_string(&val_obj)
            .map_err(|e| RiftSdkError::StoreError(format!("Serialize error: {e}")))?;

        self.store
            .set(&key, &serialized)
            .await
            .map_err(|e| RiftSdkError::StoreError(format!("Store set error: {e}")))?;
        Ok(())
    }

    async fn get_tip_leaf_hash_from_checkpoint(
        &self,
        mmr_root: &LeafDigest,
    ) -> Result<Option<LeafDigest>> {
        let key = self.make_key(&digest_to_hex(mmr_root));

        let val_opt = self
            .store
            .get(&key)
            .await
            .map_err(|e| RiftSdkError::StoreError(format!("Store get error: {e}")))?;

        if let Some(serialized) = val_opt {
            let parsed: Checkpoint = serde_json::from_str(&serialized)
                .map_err(|e| RiftSdkError::StoreError(format!("Deserialize error: {e}")))?;
            Ok(Some(parsed.tip_leaf_hash))
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
// BlockTree: a separate key prefix "block:" for (leaf_hash -> { parent_hash, index, data })
// -----------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockTreeValue {
    parent_leaf_hash: LeafDigest,
    element_index: usize,
    leaf_data: BlockLeaf,
}

#[derive(Debug)]
struct BlockTree<H: LeafHasher> {
    store: Arc<dyn Store + Send + Sync>,
    key_prefix: String,
    _phantom: std::marker::PhantomData<H>,
}

impl<H: LeafHasher> BlockTree<H> {
    fn new(store: Arc<dyn Store + Send + Sync>, key_prefix: &str) -> Self {
        Self {
            store,
            key_prefix: key_prefix.to_string(),
            _phantom: std::marker::PhantomData,
        }
    }

    fn make_key(&self, leaf_hash_hex: &str) -> String {
        format!("{}{}", self.key_prefix, leaf_hash_hex)
    }

    async fn prepare_insert(
        &self,
        parent_leaf_hash: &LeafDigest,
        leaf_data: &BlockLeaf,
        element_index: usize,
    ) -> Result<(String, String)> {
        let leaf_hash = leaf_data.hash::<H>();
        let leaf_hash_hex = digest_to_hex(&leaf_hash);
        let key = self.make_key(&leaf_hash_hex);

        let val_obj = BlockTreeValue {
            parent_leaf_hash: *parent_leaf_hash,
            element_index,
            leaf_data: *leaf_data,
        };
        let serialized = serde_json::to_string(&val_obj)
            .map_err(|e| RiftSdkError::StoreError(format!("Serialize error: {e}")))?;

        Ok((key, serialized))
    }

    async fn insert(
        &self,
        parent_leaf_hash: &LeafDigest,
        leaf_data: &BlockLeaf,
        element_index: usize,
    ) -> Result<()> {
        let (key, value) = self
            .prepare_insert(parent_leaf_hash, leaf_data, element_index)
            .await?;
        self.store
            .set(&key, &value)
            .await
            .map_err(|e| RiftSdkError::StoreError(format!("Store set error: {e}")))?;
        Ok(())
    }

    async fn batch_insert(
        &self,
        parent_leaf_hash: &LeafDigest,
        leaves: &[BlockLeaf],
        element_indices: &[usize],
    ) -> Result<()> {
        let mut entries = HashMap::new();

        let mut parent_leaf_hash = *parent_leaf_hash;
        assert_eq!(leaves.len(), element_indices.len());
        for (i, leaf) in leaves.iter().enumerate() {
            let (key, value) = self
                .prepare_insert(&parent_leaf_hash, leaf, element_indices[i])
                .await?;
            entries.insert(key, value);
            parent_leaf_hash = leaf.hash::<H>();
        }

        self.store
            .set_many(entries)
            .await
            .map_err(|e| RiftSdkError::StoreError(format!("Store set_many error: {e}")))?;
        Ok(())
    }

    async fn get_by_leaf_hash(&self, leaf_digest: &LeafDigest) -> Result<Option<BlockTreeValue>> {
        let leaf_hash_hex = digest_to_hex(leaf_digest);
        let key = self.make_key(&leaf_hash_hex);

        let val_opt = self
            .store
            .get(&key)
            .await
            .map_err(|e| RiftSdkError::StoreError(format!("Store get error: {e}")))?;

        if let Some(serialized) = val_opt {
            let parsed: BlockTreeValue = serde_json::from_str(&serialized)
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

    /// Find the Lowest Common Ancestor (LCA) between two leaf hashes in the block tree.
    /// Returns the LCA leaf hash, and the paths from the LCA to the two leaves.
    async fn find_lca(
        &self,
        leaf1: &BlockTreeValue,
        leaf2: &BlockTreeValue,
    ) -> Result<(LeafDigest, Vec<BlockTreeValue>, Vec<BlockTreeValue>)> {
        // Get the height of each leaf from root
        let height1 = leaf1.leaf_data.height;
        let height2 = leaf2.leaf_data.height;

        // Initialize current nodes
        let mut curr1 = leaf1.clone();
        let mut curr2 = leaf2.clone();

        // Determine which node is lower in the tree
        let (mut lower_node, mut higher_node, height_diff) = if height1 > height2 {
            (curr1, curr2, height1 - height2)
        } else {
            (curr2, curr1, height2 - height1)
        };

        // Store original identities to properly construct return paths
        let is_leaf1_lower = height1 > height2;

        // Initialize paths - we'll build these during traversal
        let mut path_from_lower = vec![lower_node.clone()];
        let mut path_from_higher = vec![higher_node.clone()];

        // Move the lower node up until both nodes are at the same height
        for _ in 0..height_diff {
            let parent_leaf_hash = lower_node.parent_leaf_hash;
            if parent_leaf_hash == NULL_LEAF_HASH {
                return Err(RiftSdkError::MMRError(
                    "Already traversed to the root without finding LCA".to_string(),
                ));
            }
            let parent_node = self
                .get_by_leaf_hash(&parent_leaf_hash)
                .await?
                .ok_or_else(|| RiftSdkError::MMRError("Parent node not found".to_string()))?;

            lower_node = parent_node.clone();
            path_from_lower.push(lower_node.clone());
        }

        // Move both nodes up until they meet at the LCA
        while lower_node.leaf_data.hash::<H>() != higher_node.leaf_data.hash::<H>() {
            let lower_parent = lower_node.parent_leaf_hash;
            let higher_parent = higher_node.parent_leaf_hash;

            if lower_parent == NULL_LEAF_HASH || higher_parent == NULL_LEAF_HASH {
                return Err(RiftSdkError::MMRError(
                    "Reached root without finding LCA".to_string(),
                ));
            }

            let lower_parent_node = self
                .get_by_leaf_hash(&lower_parent)
                .await?
                .ok_or_else(|| RiftSdkError::MMRError("Parent node not found".to_string()))?;
            let higher_parent_node = self
                .get_by_leaf_hash(&higher_parent)
                .await?
                .ok_or_else(|| RiftSdkError::MMRError("Parent node not found".to_string()))?;

            lower_node = lower_parent_node.clone();
            higher_node = higher_parent_node.clone();

            path_from_lower.push(lower_node.clone());
            path_from_higher.push(higher_node.clone());
        }

        // At this point, lower_node and higher_node are the same node (the LCA)

        let lca_hash = lower_node.leaf_data.hash::<H>();
        println!("LCA node: {:?}", lower_node);
        println!("✓ Found LCA [inside find_lca]: {:?}", lca_hash);

        // Remove the LCA from both paths
        path_from_lower.pop();
        path_from_higher.pop();

        // Construct the paths from LCA to each leaf
        let path_to_leaf1;
        let path_to_leaf2;

        if is_leaf1_lower {
            // leaf1 was the lower node
            path_to_leaf1 = path_from_lower;
            path_to_leaf2 = path_from_higher;
        } else {
            // leaf2 was the lower node
            path_to_leaf1 = path_from_higher;
            path_to_leaf2 = path_from_lower;
        }

        // Reverse the paths so they go from LCA to leaves
        let leaf1_path_from_lca = path_to_leaf1.into_iter().rev().collect();
        let leaf2_path_from_lca = path_to_leaf2.into_iter().rev().collect();

        Ok((lca_hash, leaf1_path_from_lca, leaf2_path_from_lca))
    }
}

// Reusing helper functions from the original code
pub fn digest_to_hex(digest: &LeafDigest) -> String {
    format!("0x{}", hex::encode(digest))
}

// -----------------------------------------------------------------------------
// CheckpointedBlockTree: Main struct wrapping IndexedMMR with new functionality
// -----------------------------------------------------------------------------
#[derive(Debug)]
pub struct CheckpointedBlockTree<H: LeafHasher> {
    indexed_mmr: IndexedMMR<H>,
    block_tree: BlockTree<H>,
    checkpoint_map: CheckpointMap,
}

impl<H: LeafHasher> CheckpointedBlockTree<H> {
    /// Create a new CheckpointedBlockTree using an existing or new IndexedMMR
    pub async fn open(database_location: &DatabaseLocation) -> Result<Self> {
        // Create the underlying store
        let store: Arc<dyn Store + Send + Sync> = match database_location {
            DatabaseLocation::InMemory => Arc::new(InMemoryStore::default()),
            DatabaseLocation::Directory(path) => {
                let db_path = PathBuf::from(path).join("checkpoints.db");
                let db_path_str = db_path.to_str().expect("Invalid path");
                let sqlite = SQLiteStore::new(db_path_str, Some(true), None)
                    .await
                    .map_err(|e| RiftSdkError::StoreError(e.to_string()))?;
                Arc::new(sqlite)
            }
        };

        // Create IndexedMMR
        let indexed_mmr = IndexedMMR::<H>::open(database_location).await?;

        // Create BlockTree and CheckpointMap
        let block_tree = BlockTree::new(store.clone(), "block:");
        let checkpoint_map = CheckpointMap::new(store.clone(), "checkpoint:");

        Ok(Self {
            indexed_mmr,
            block_tree,
            checkpoint_map,
        })
    }

    /// Creates a seed checkpoint for an empty MMR with the genesis block
    /// Should be called only once when the underlying IndexedMMR is empty
    pub async fn create_seed_checkpoint(&mut self, blocks: &[BlockLeaf]) -> Result<LeafDigest> {
        // Check if MMR is empty
        let leaf_count = self.indexed_mmr.get_leaf_count().await?;
        if leaf_count > 0 {
            return Err(RiftSdkError::MMRError(
                "Cannot create seed checkpoint: MMR is not empty".into(),
            ));
        }

        // Append the genesis block
        // get the element indices
        let result = self.indexed_mmr.batch_append(blocks).await?;

        let element_indices = result
            .iter()
            .map(|r| r.element_index)
            .collect::<Vec<usize>>();

        self.block_tree
            .batch_insert(&NULL_LEAF_HASH, blocks, &element_indices)
            .await?;

        // Create the checkpoint
        let mmr_root = self.indexed_mmr.get_root().await?;
        let tip_block_hash = blocks.last().unwrap().hash::<H>();
        self.checkpoint_map
            .insert(&mmr_root, &tip_block_hash)
            .await?;

        Ok(mmr_root)
    }

    /// Main function to update the chain from a checkpoint
    /// This is the primary state-modifying function after initial creation
    pub async fn update_from_checkpoint(
        &mut self,
        prior_checkpoint_mmr_root: &LeafDigest,
        new_blocks: &[BlockLeaf],
    ) -> Result<LeafDigest> {
        if new_blocks.is_empty() {
            return Err(RiftSdkError::MMRError(
                "No blocks provided for update".into(),
            ));
        }

        // Get the checkpoint's tip leaf hash
        let prior_checkpoint_leaf_hash = self
            .checkpoint_map
            .get_tip_leaf_hash_from_checkpoint(prior_checkpoint_mmr_root)
            .await?
            .ok_or_else(|| RiftSdkError::MMRError("Checkpoint not found".to_string()))?;

        // Get the BlockTreeValue for the checkpoint's tip
        let prior_checkpoint_tip_block_tree_value = self
            .block_tree
            .get_by_leaf_hash(&prior_checkpoint_leaf_hash)
            .await?
            .ok_or_else(|| {
                RiftSdkError::MMRError("Checkpoint leaf not found in block tree".to_string())
            })?;

        // Get the current tip
        let current_tip_leaf_index = self.indexed_mmr.get_leaf_count().await? as i64 - 1;
        if current_tip_leaf_index < 0 {
            return Err(RiftSdkError::MMRError("Chain is empty".to_string()));
        }

        let current_tip_leaf = self
            .indexed_mmr
            .get_leaf_by_leaf_index(current_tip_leaf_index as usize)
            .await?
            .ok_or_else(|| RiftSdkError::MMRError("Tip leaf not found".to_string()))?;

        let current_tip_leaf_hash = current_tip_leaf.hash::<H>();
        let current_tip_block_tree_value = self
            .block_tree
            .get_by_leaf_hash(&current_tip_leaf_hash)
            .await?
            .ok_or_else(|| {
                RiftSdkError::MMRError("Current tip not found in block tree".to_string())
            })?;

        // Find the lowest common ancestor (LCA)
        let (lca_leaf_hash, current_tip_path, prior_checkpoint_tip_path) = self
            .block_tree
            .find_lca(
                &current_tip_block_tree_value,
                &prior_checkpoint_tip_block_tree_value,
            )
            .await?;

        println!("✓ Found LCA: {}", digest_to_hex(&lca_leaf_hash));
        // Get the leaf @ lca_leaf_hash
        let (lca_leaf_element_index, _) = self
            .indexed_mmr
            .get_leaf_by_leaf_hash(&lca_leaf_hash)
            .await?
            .ok_or_else(|| RiftSdkError::MMRError("LCA leaf not found in the MMR".to_string()))?;

        // Rewind the MMR to the LCA
        let lca_leaf_index = element_index_to_leaf_index(lca_leaf_element_index)
            .map_err(|e| RiftSdkError::MMRError(format!("Failed to convert to leaf index: {e}")))?;

        // Rewind IndexedMMR to LCA
        self.indexed_mmr.rewind(lca_leaf_index).await?;

        // Re-append the leaves from LCA to prior checkpoint tip
        let leaves_to_append = prior_checkpoint_tip_path
            .iter()
            .map(|v| v.leaf_data)
            .collect::<Vec<BlockLeaf>>();

        // Append to IndexedMMR
        for leaf in &leaves_to_append {
            self.indexed_mmr.append(leaf).await?;
        }

        // Now append the new blocks
        let mut prev_leaf_hash = prior_checkpoint_leaf_hash;
        for block in new_blocks {
            // Append to IndexedMMR
            let append_res = self.indexed_mmr.append(block).await?;

            // Record in block tree
            let block_hash = block.hash::<H>();
            self.block_tree
                .insert(&prev_leaf_hash, block, append_res.element_index)
                .await?;

            prev_leaf_hash = block_hash;
        }

        // Create a new checkpoint
        let new_checkpoint_mmr_root = self.indexed_mmr.get_root().await?;
        let tip_hash = new_blocks.last().unwrap().hash::<H>();

        // Store the checkpoint
        self.checkpoint_map
            .insert(&new_checkpoint_mmr_root, &tip_hash)
            .await?;

        Ok(new_checkpoint_mmr_root)
    }

    // Delegate methods to access IndexedMMR functionality (read-only)

    pub async fn get_root(&self) -> Result<LeafDigest> {
        self.indexed_mmr.get_root().await
    }

    pub async fn get_leaf_by_leaf_hash(
        &self,
        leaf_hash: &LeafDigest,
    ) -> Result<Option<(usize, BlockLeaf)>> {
        self.indexed_mmr.get_leaf_by_leaf_hash(leaf_hash).await
    }

    pub async fn get_leaf_by_leaf_index(&self, leaf_index: usize) -> Result<Option<BlockLeaf>> {
        self.indexed_mmr.get_leaf_by_leaf_index(leaf_index).await
    }

    pub async fn get_leaf_count(&self) -> Result<usize> {
        self.indexed_mmr.get_leaf_count().await
    }

    pub async fn get_client_proof(
        &self,
        leaf_index: usize,
        elements_count: Option<usize>,
    ) -> Result<ClientMMRProof> {
        self.indexed_mmr
            .get_client_proof(leaf_index, elements_count)
            .await
    }

    pub async fn get_circuit_proof(
        &self,
        leaf_index: usize,
        elements_count: Option<usize>,
    ) -> Result<CircuitMMRProof> {
        self.indexed_mmr
            .get_circuit_proof(leaf_index, elements_count)
            .await
    }

    pub async fn get_bagged_peak(&self) -> Result<LeafDigest> {
        self.indexed_mmr.get_bagged_peak().await
    }

    pub async fn get_peaks(&self, elements_count: Option<usize>) -> Result<Vec<LeafDigest>> {
        self.indexed_mmr.get_peaks(elements_count).await
    }
}

// -----------------------------------------------------------------------------
// Tests for CheckpointedBlockTree
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_light_client_core::hasher::Keccak256Hasher;

    #[tokio::test]
    async fn test_checkpoint_mmr_reorg() -> Result<()> {
        println!("\n=== Starting Checkpoint MMR Test ===\n");

        let mut checkpointed_blocktree =
            CheckpointedBlockTree::<Keccak256Hasher>::open(&DatabaseLocation::InMemory).await?;
        println!("✓ Created new CheckpointedBlockTree in memory");

        // Create the genesis block
        let genesis_block = BlockLeaf {
            block_hash: [0; 32],
            cumulative_chainwork: [1; 32],
            height: 0,
        };
        println!(
            "✓ Created genesis block leaf hash: {}",
            digest_to_hex(&genesis_block.hash::<Keccak256Hasher>())
        );

        // Step 1: Create the seed checkpoint
        let seed_checkpoint_root = checkpointed_blocktree
            .create_seed_checkpoint(&[genesis_block])
            .await?;
        println!("✓ Created seed checkpoint with genesis block");
        println!(
            "  Seed checkpoint root: {}",
            digest_to_hex(&seed_checkpoint_root)
        );

        // Verify seed checkpoint was created
        let leaf_count = checkpointed_blocktree.get_leaf_count().await?;
        assert_eq!(leaf_count, 1); // Only the genesis block
        println!("✓ Verified seed checkpoint has 1 leaf (genesis block)");

        // Create a fork A: genesis -> A1 -> A2
        let a1_block = BlockLeaf {
            block_hash: [1; 32],
            cumulative_chainwork: [2; 32],
            height: 1,
        };

        let a2_block = BlockLeaf {
            block_hash: [2; 32],
            cumulative_chainwork: [3; 32],
            height: 2,
        };

        // Step 2: Update from the seed checkpoint with fork A
        let checkpoint_a = checkpointed_blocktree
            .update_from_checkpoint(&seed_checkpoint_root, &[a1_block, a2_block])
            .await?;
        println!("✓ Created fork A: genesis -> A1 -> A2");
        println!("  Checkpoint A root: {}", digest_to_hex(&checkpoint_a));

        // Verify checkpoint A
        let leaf_count = checkpointed_blocktree.get_leaf_count().await?;
        assert_eq!(leaf_count, 3); // genesis + A1 + A2
        println!("✓ Verified fork A has 3 leaves (genesis + A1 + A2)");

        // Create a fork B: genesis -> B1 -> B2 -> B3 (with higher chainwork)
        let b1_block = BlockLeaf {
            block_hash: [3; 32],
            cumulative_chainwork: [4; 32], // Higher chainwork than A
            height: 1,
        };

        let b2_block = BlockLeaf {
            block_hash: [4; 32],
            cumulative_chainwork: [5; 32],
            height: 2,
        };

        let b3_block = BlockLeaf {
            block_hash: [5; 32],
            cumulative_chainwork: [6; 32],
            height: 3,
        };

        // Step 3: Update from the seed checkpoint with fork B
        // This will reorg from fork A to fork B
        let checkpoint_b = checkpointed_blocktree
            .update_from_checkpoint(&seed_checkpoint_root, &[b1_block, b2_block, b3_block])
            .await?;
        println!("✓ Created fork B: genesis -> B1 -> B2 -> B3");
        println!("  Checkpoint B root: {}", digest_to_hex(&checkpoint_b));
        println!("  Note: This reorged from fork A to fork B due to higher chainwork");

        // Verify the chain is now on fork B
        let leaf_count = checkpointed_blocktree.get_leaf_count().await?;
        assert_eq!(leaf_count, 4); // genesis + B1 + B2 + B3
        println!("✓ Verified fork B has 4 leaves (genesis + B1 + B2 + B3)");

        // Verify B3 is in the chain but A2 is not
        let b3_hash = b3_block.hash::<Keccak256Hasher>();
        let a2_hash = a2_block.hash::<Keccak256Hasher>();

        let b3_exists = checkpointed_blocktree
            .get_leaf_by_leaf_hash(&b3_hash)
            .await?;
        let a2_exists = checkpointed_blocktree
            .get_leaf_by_leaf_hash(&a2_hash)
            .await?;

        assert!(b3_exists.is_some(), "Block B3 should be in the chain");
        assert!(
            a2_exists.is_none(),
            "Block A2 should not be in the chain after reorg"
        );
        println!("✓ Verified B3 is in chain and A2 is not (reorg successful)");

        // Step 4: Update again from checkpoint B with more blocks
        let b4_block = BlockLeaf {
            block_hash: [6; 32],
            cumulative_chainwork: [7; 32],
            height: 4,
        };

        let b5_block = BlockLeaf {
            block_hash: [7; 32],
            cumulative_chainwork: [8; 32],
            height: 5,
        };

        let checkpoint_b_extended = checkpointed_blocktree
            .update_from_checkpoint(&checkpoint_b, &[b4_block, b5_block])
            .await?;
        println!("✓ Extended fork B with B4 and B5");
        println!(
            "  Extended checkpoint root: {}",
            digest_to_hex(&checkpoint_b_extended)
        );

        // Verify the chain has extended properly
        let leaf_count = checkpointed_blocktree.get_leaf_count().await?;
        assert_eq!(leaf_count, 6); // genesis + B1 + B2 + B3 + B4 + B5
        println!("✓ Verified extended chain has 6 leaves");

        println!("\n=== Checkpoint MMR Test Completed Successfully ===\n");
        Ok(())
    }

    #[tokio::test]
    // 1. seed with genesis (seed_checkpoint)
    // 2. create a chain of 4 blocks total (genesis, A1, A2, A3), (create checkpoint A)
    // 3. create a chain with 2 total blocks (genesis, B1) (create checkpoint B)
    // 4. Validate all the original blocks A1, A2, A3 are no longer in the MMR
    // 5. Validate chain length is 2
    // 6. Create a new block C1, that builds from checkpoint A
    // 7. Validate C1 is in the chain
    // 8. Validate chain length is 5
    async fn test_checkpoint_mmr_reenable_old_fork() -> Result<()> {
        println!("\n=== Starting Checkpoint MMR Reenable Old Fork Test ===\n");

        // 1) Create a new CheckpointedBlockTree in memory and seed with genesis
        let mut checkpointed_blocktree =
            CheckpointedBlockTree::<Keccak256Hasher>::open(&DatabaseLocation::InMemory).await?;
        println!("✓ Created new CheckpointedBlockTree in memory");

        // Create the genesis block
        let genesis_block = BlockLeaf {
            block_hash: [0; 32],
            cumulative_chainwork: [1; 32],
            height: 0,
        };
        println!(
            "✓ Created genesis block leaf hash: {}",
            digest_to_hex(&genesis_block.hash::<Keccak256Hasher>())
        );

        // Seed checkpoint with genesis
        let seed_checkpoint_root = checkpointed_blocktree
            .create_seed_checkpoint(&[genesis_block])
            .await?;
        println!("✓ Created seed checkpoint with genesis block");
        println!(
            "  Seed checkpoint root: {}",
            digest_to_hex(&seed_checkpoint_root)
        );

        // Verify we have 1 leaf
        let leaf_count = checkpointed_blocktree.get_leaf_count().await?;
        assert_eq!(leaf_count, 1, "Expected 1 leaf after seeding");
        println!("✓ Verified chain has 1 leaf (genesis)\n");

        // 2) Build fork A: genesis -> A1 -> A2 -> A3
        let a1_block = BlockLeaf {
            block_hash: [1; 32],
            cumulative_chainwork: [2; 32],
            height: 1,
        };
        let a2_block = BlockLeaf {
            block_hash: [2; 32],
            cumulative_chainwork: [3; 32],
            height: 2,
        };
        let a3_block = BlockLeaf {
            block_hash: [3; 32],
            cumulative_chainwork: [4; 32],
            height: 3,
        };

        let checkpoint_a = checkpointed_blocktree
            .update_from_checkpoint(&seed_checkpoint_root, &[a1_block, a2_block, a3_block])
            .await?;
        println!("✓ Created fork A (genesis → A1 → A2 → A3)");
        println!("  Checkpoint A root: {}", digest_to_hex(&checkpoint_a));

        let leaf_count = checkpointed_blocktree.get_leaf_count().await?;
        assert_eq!(leaf_count, 4, "Expected 4 leaves on chain A");
        println!("✓ Verified fork A has 4 leaves (genesis + A1 + A2 + A3)\n");

        // 3) Build fork B: genesis -> B1 from the seed checkpoint
        let b1_block = BlockLeaf {
            block_hash: [4; 32],
            cumulative_chainwork: [10; 32], // Suppose this is "higher" or separate chainwork
            height: 1,
        };

        let checkpoint_b = checkpointed_blocktree
            .update_from_checkpoint(&seed_checkpoint_root, &[b1_block])
            .await?;
        println!("✓ Created fork B (genesis → B1)");
        println!("  Checkpoint B root: {}", digest_to_hex(&checkpoint_b));

        // The chain is now reorged to B, so length should be 2
        let leaf_count = checkpointed_blocktree.get_leaf_count().await?;
        assert_eq!(
            leaf_count, 2,
            "Expected 2 leaves after reorg to fork B (genesis + B1)"
        );
        println!("✓ Verified fork B has 2 leaves (genesis + B1)");

        // 4) Verify A1, A2, A3 are not in the chain anymore
        let a1_hash = a1_block.hash::<Keccak256Hasher>();
        let a2_hash = a2_block.hash::<Keccak256Hasher>();
        let a3_hash = a3_block.hash::<Keccak256Hasher>();

        assert!(
            checkpointed_blocktree
                .get_leaf_by_leaf_hash(&a1_hash)
                .await?
                .is_none(),
            "A1 should not be in chain after reorg to B"
        );
        assert!(
            checkpointed_blocktree
                .get_leaf_by_leaf_hash(&a2_hash)
                .await?
                .is_none(),
            "A2 should not be in chain after reorg to B"
        );
        assert!(
            checkpointed_blocktree
                .get_leaf_by_leaf_hash(&a3_hash)
                .await?
                .is_none(),
            "A3 should not be in chain after reorg to B"
        );
        println!("✓ Verified A1, A2, and A3 are removed from the current chain\n");

        // 5) Build on top of checkpoint A with a new block C1
        let c1_block = BlockLeaf {
            block_hash: [5; 32],
            cumulative_chainwork: [11; 32],
            height: 4,
        };

        let checkpoint_c = checkpointed_blocktree
            .update_from_checkpoint(&checkpoint_a, &[c1_block])
            .await?;
        println!("✓ Extended old fork A with C1 (genesis → A1 → A2 → A3 → C1)");
        println!("  New checkpoint root: {}", digest_to_hex(&checkpoint_c));

        // 6) Verify final chain includes A1, A2, A3, and C1
        let leaf_count = checkpointed_blocktree.get_leaf_count().await?;
        assert_eq!(
            leaf_count, 5,
            "Expected 5 leaves: genesis + A1 + A2 + A3 + C1"
        );
        println!("✓ Verified chain reactivated old fork + C1 has 5 leaves");

        // A1, A2, A3, and C1 should now be present again
        assert!(
            checkpointed_blocktree
                .get_leaf_by_leaf_hash(&a1_hash)
                .await?
                .is_some(),
            "A1 must be back in the chain"
        );
        assert!(
            checkpointed_blocktree
                .get_leaf_by_leaf_hash(&a2_hash)
                .await?
                .is_some(),
            "A2 must be back in the chain"
        );
        assert!(
            checkpointed_blocktree
                .get_leaf_by_leaf_hash(&a3_hash)
                .await?
                .is_some(),
            "A3 must be back in the chain"
        );

        let c1_hash = c1_block.hash::<Keccak256Hasher>();
        assert!(
            checkpointed_blocktree
                .get_leaf_by_leaf_hash(&c1_hash)
                .await?
                .is_some(),
            "C1 must be in the chain"
        );

        // 7) Verify B1 is gone now that we reorged from checkpoint A
        let b1_hash = b1_block.hash::<Keccak256Hasher>();
        assert!(
            checkpointed_blocktree
                .get_leaf_by_leaf_hash(&b1_hash)
                .await?
                .is_none(),
            "B1 should not be in the chain after reorg to old fork + C1"
        );

        println!("✓ Verified B1 is removed after reactivating old fork A\n");
        println!("=== Checkpoint MMR Reenable Old Fork Test Completed ===\n");

        Ok(())
    }

    #[tokio::test]
    // 1. seed with genesis (seed_checkpoint)
    // 2. create a chain of 4 blocks total (genesis, A1, A2, A3), (create checkpoint A)
    // 3. create a new block A4, that builds from checkpoint A
    // 4. validate A4 is in the chain
    // 5. validate chain length is 5
    async fn test_checkpoint_mmr_simple_append() -> Result<()> {
        println!("\n=== Starting Checkpoint MMR Simple Append Test ===\n");

        // 1) Create a new CheckpointedBlockTree in memory and seed with genesis
        let mut checkpointed_blocktree =
            CheckpointedBlockTree::<Keccak256Hasher>::open(&DatabaseLocation::InMemory).await?;
        println!("✓ Created new CheckpointedBlockTree in memory");

        // Create the genesis block
        let genesis_block = BlockLeaf {
            block_hash: [0; 32],
            cumulative_chainwork: [1; 32],
            height: 0,
        };
        println!(
            "✓ Created genesis block leaf hash: {}",
            digest_to_hex(&genesis_block.hash::<Keccak256Hasher>())
        );

        // Seed checkpoint with genesis
        let seed_checkpoint_root = checkpointed_blocktree
            .create_seed_checkpoint(&[genesis_block])
            .await?;
        println!("✓ Created seed checkpoint with genesis block");
        println!(
            "  Seed checkpoint root: {}",
            digest_to_hex(&seed_checkpoint_root)
        );

        // Verify we have 1 leaf
        let leaf_count = checkpointed_blocktree.get_leaf_count().await?;
        assert_eq!(leaf_count, 1, "Expected 1 leaf after seeding");
        println!("✓ Verified chain has 1 leaf (genesis)\n");

        // 2) Build a chain of 4 total blocks: genesis -> A1 -> A2 -> A3
        let a1_block = BlockLeaf {
            block_hash: [1; 32],
            cumulative_chainwork: [2; 32],
            height: 1,
        };
        let a2_block = BlockLeaf {
            block_hash: [2; 32],
            cumulative_chainwork: [3; 32],
            height: 2,
        };
        let a3_block = BlockLeaf {
            block_hash: [3; 32],
            cumulative_chainwork: [4; 32],
            height: 3,
        };

        // Append A1, A2, A3 to create checkpoint A
        let checkpoint_a = checkpointed_blocktree
            .update_from_checkpoint(&seed_checkpoint_root, &[a1_block, a2_block, a3_block])
            .await?;
        println!("✓ Created chain A (genesis → A1 → A2 → A3)");
        println!("  Checkpoint A root: {}", digest_to_hex(&checkpoint_a));

        // Verify chain length: 4 blocks total
        let leaf_count = checkpointed_blocktree.get_leaf_count().await?;
        assert_eq!(leaf_count, 4, "Expected 4 leaves (genesis + A1 + A2 + A3)");
        println!("✓ Verified chain has 4 leaves\n");

        // 3) From checkpoint A, append a new block A4
        let a4_block = BlockLeaf {
            block_hash: [4; 32],
            cumulative_chainwork: [5; 32],
            height: 4,
        };
        let checkpoint_a_extended = checkpointed_blocktree
            .update_from_checkpoint(&checkpoint_a, &[a4_block])
            .await?;
        println!("✓ Appended A4 on top of checkpoint A (genesis → A1 → A2 → A3 → A4)");
        println!(
            "  Extended checkpoint root: {}",
            digest_to_hex(&checkpoint_a_extended)
        );

        // 4) Verify that A4 is in the chain
        let a4_hash = a4_block.hash::<Keccak256Hasher>();
        let a4_exists = checkpointed_blocktree
            .get_leaf_by_leaf_hash(&a4_hash)
            .await?
            .is_some();
        assert!(a4_exists, "A4 must be present in the chain");
        println!("✓ Verified A4 is in the chain\n");

        // 5) Verify chain length is now 5
        let leaf_count = checkpointed_blocktree.get_leaf_count().await?;
        assert_eq!(
            leaf_count, 5,
            "Expected 5 leaves (genesis + A1 + A2 + A3 + A4)"
        );
        println!("✓ Verified final chain has 5 leaves");

        println!("=== Checkpoint MMR Simple Append Test Completed ===\n");
        Ok(())
    }
}
