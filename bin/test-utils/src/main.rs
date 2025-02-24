use std::io::Read;

use accumulators::mmr::map_leaf_index_to_element_index;
use alloy::{
    dyn_abi::{abi::encode, DynSolType, DynSolValue},
    hex,
    primitives::{FixedBytes, U256},
    sol,
    sol_types::SolValue,
};
use bitcoin_light_client_core::{
    hasher::{Digest, Hasher},
    leaves::BlockLeaf,
    mmr::verify_mmr_proof,
};
use clap::{Parser, Subcommand};

use bitcoin_light_client_core::hasher::Keccak256Hasher;
use rift_sdk::mmr::{client_mmr_proof_to_circuit_mmr_proof, client_mmr_to_root, digest_to_hex};
use rift_sdk::{mmr::IndexedMMR, DatabaseLocation};

const BLOCK_HASH_SEED: [u8; 32] =
    hex!("ceeca7c42d523ea6b5183e5922b966e85d1dab847b051e18ffd3611763726626");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a deterministic fake block MMR proof for testing
    GenerateFakeBlockMMRProof {
        #[arg(short, long)]
        height: u32,

        #[arg(short, long)]
        debug: bool,
    },
    /// Generate a deterministic fake block with proofs based on the confirmation block height for testing
    GenerateFakeBlockWithConfirmationsMMRProof {
        #[arg(short, long)]
        height: u32,

        #[arg(short, long)]
        confirmations: u32,

        #[arg(short, long)]
        debug: bool,
    },
    /// Hash a block leaf
    HashBlockLeaf {
        #[arg(short, long)]
        abi_encoded_leaf: String,
    },
}

fn generate_block_hashes(height: u32) -> Vec<Digest> {
    let mut block_hashes = vec![];
    for i in 0..=height {
        let mut data = format!("block_hash_{}", i).into_bytes();
        data.extend_from_slice(&BLOCK_HASH_SEED);
        block_hashes.push(Keccak256Hasher::hash(&data));
    }
    block_hashes
}

fn mock_chainwork_for_height(height: u32) -> U256 {
    // Arbitrary chainwork scalar for demonstration
    U256::from((height + 1) * 1_000_000)
}

/// Generates a fake MMR proof for the block at `height`, using an MMR built from block 0..=height.
async fn generate_fake_block_mmr_proof(height: u32, debug: bool) {
    let block_hashes = generate_block_hashes(height);
    let mmr_db_location = DatabaseLocation::InMemory;
    let mut indexed_mmr = IndexedMMR::<Keccak256Hasher>::open(&mmr_db_location)
        .await
        .unwrap();

    // Create and append MMR leaves (blocks 0..=height)
    for (i, hash) in block_hashes.iter().enumerate() {
        let leaf = BlockLeaf::new(
            *hash,
            i as u32,
            mock_chainwork_for_height(i as u32).to_be_bytes(),
        );
        indexed_mmr.append(&leaf).await.unwrap();
    }

    // Prepare the block leaf for the final block at `height`
    let block_leaf = rift_sdk::bindings::non_artifacted_types::Types::BlockLeaf {
        blockHash: block_hashes[height as usize].into(),
        height,
        cumulativeChainwork: mock_chainwork_for_height(height),
    };

    // Get a proof for the leaf at `height`
    let leaf_index = height as usize;
    let circuit_proof = indexed_mmr
        .get_circuit_proof(leaf_index, None)
        .await
        .unwrap();

    // MMR root
    let root_hash = indexed_mmr.get_root().await.unwrap();

    if debug {
        println!("proof: {:?}", circuit_proof);
        println!("root_hash: {}", hex::encode(root_hash));
    }

    // Optional debug check: verify the proof
    if debug {
        assert!(
            verify_mmr_proof::<Keccak256Hasher>(&root_hash, &circuit_proof),
            "MMR proof verification failed"
        );
    }

    // Convert to Solidity-friendly ABI-encoded proof
    let siblings: Vec<FixedBytes<32>> = circuit_proof
        .siblings
        .iter()
        .map(|s| s.into())
        .collect::<Vec<_>>();
    let peaks: Vec<FixedBytes<32>> = circuit_proof
        .peaks
        .iter()
        .map(|s| s.into())
        .collect::<Vec<_>>();
    let tip_block_height = height;
    let root_hash: FixedBytes<32> = root_hash.into();
    let sol_mmr_proof = rift_sdk::bindings::non_artifacted_types::Types::MMRProof {
        blockLeaf: block_leaf,
        siblings,
        peaks,
        leafCount: tip_block_height + 1,
        mmrRoot: root_hash,
    };

    println!("{}", hex::encode(sol_mmr_proof.abi_encode()));
}

/// Generates a fake MMR proof for the block at `height`, but the MMR is built up to
/// `height + confirmations`. This proves that the block at `height` is included in
/// the chain up to (and including) the tip `height + confirmations`.
///
/// **Additionally**, we also retrieve a proof for the **tip block** itself, so you
/// can see that block's MMR proof in the same chain.
async fn generate_fake_block_with_confirmations_mmr_proof(
    height: u32,
    confirmations: u32,
    debug: bool,
) {
    let tip_height = height + confirmations;
    let block_hashes = generate_block_hashes(tip_height);
    let mut indexed_mmr = IndexedMMR::<Keccak256Hasher>::open(&DatabaseLocation::InMemory)
        .await
        .unwrap();

    // Create and append MMR leaves (blocks 0..=tip_height)
    for (i, hash) in block_hashes.iter().enumerate() {
        let leaf = BlockLeaf::new(
            *hash,
            i as u32,
            mock_chainwork_for_height(i as u32).to_be_bytes(),
        );
        indexed_mmr.append(&leaf).await.unwrap();
    }

    // 1) Get proof for the block at `height`
    let block_leaf = rift_sdk::bindings::non_artifacted_types::Types::BlockLeaf {
        blockHash: block_hashes[height as usize].into(),
        height,
        cumulativeChainwork: mock_chainwork_for_height(height),
    };

    let leaf_index = height as usize;
    let proof = indexed_mmr
        .get_circuit_proof(leaf_index, None)
        .await
        .unwrap();

    // 2) Also get a proof for the *tip* block at `tip_height`
    let tip_block_leaf = rift_sdk::bindings::non_artifacted_types::Types::BlockLeaf {
        blockHash: block_hashes[tip_height as usize].into(),
        height: tip_height,
        cumulativeChainwork: mock_chainwork_for_height(tip_height),
    };
    let tip_leaf_index = tip_height as usize;
    let tip_proof = indexed_mmr
        .get_circuit_proof(tip_leaf_index, None)
        .await
        .unwrap();

    // The MMR root for the entire chain up to the tip
    let root_hash = indexed_mmr.get_root().await.unwrap();

    if debug {
        println!("Using tip_height: {}", tip_height);
        println!("Proof for block @{}: {:?}", height, proof);
        println!("Proof for tip block @{}: {:?}", tip_height, tip_proof);
        println!("root_hash: {}", hex::encode(root_hash));
    }

    // Optional debug checks: verify both proofs
    if debug {
        assert!(
            verify_mmr_proof::<Keccak256Hasher>(&root_hash, &proof),
            "MMR proof verification for block at `height` failed"
        );
        assert!(
            verify_mmr_proof::<Keccak256Hasher>(&root_hash, &tip_proof),
            "MMR proof verification for tip block failed"
        );
    }

    // Convert both to Solidity-friendly ABI-encoded proofs

    // 1) The block's proof
    let siblings: Vec<FixedBytes<32>> = proof.siblings.iter().map(|s| s.into()).collect::<Vec<_>>();
    let peaks: Vec<FixedBytes<32>> = proof.peaks.iter().map(|s| s.into()).collect::<Vec<_>>();
    let leaf_count = tip_height + 1;
    let root_hash_fixed: FixedBytes<32> = root_hash.into();
    let sol_mmr_proof = rift_sdk::bindings::non_artifacted_types::Types::MMRProof {
        blockLeaf: block_leaf,
        siblings,
        peaks,
        leafCount: leaf_count,
        mmrRoot: root_hash_fixed,
    };

    // 2) The tip block's proof
    let tip_siblings: Vec<FixedBytes<32>> = tip_proof
        .siblings
        .iter()
        .map(|s| s.into())
        .collect::<Vec<_>>();
    let tip_peaks: Vec<FixedBytes<32>> =
        tip_proof.peaks.iter().map(|s| s.into()).collect::<Vec<_>>();
    let tip_sol_mmr_proof = rift_sdk::bindings::non_artifacted_types::Types::MMRProof {
        blockLeaf: tip_block_leaf,
        siblings: tip_siblings,
        peaks: tip_peaks,
        leafCount: leaf_count,
        mmrRoot: root_hash_fixed,
    };

    let full_proof = rift_sdk::bindings::non_artifacted_types::Types::ReleaseMMRProof {
        proof: sol_mmr_proof,
        tipProof: tip_sol_mmr_proof,
    };

    println!("{}", hex::encode(full_proof.abi_encode()));
}

async fn hash_block_leaf(abi_encoded_leaf: &str) {
    let abi_encoded_leaf = hex::decode(abi_encoded_leaf.strip_prefix("0x").unwrap()).unwrap();
    let sol_leaf = rift_sdk::bindings::non_artifacted_types::Types::BlockLeaf::abi_decode(
        &abi_encoded_leaf,
        false,
    )
    .unwrap();

    let core_leaf = BlockLeaf::new(
        sol_leaf.blockHash.into(),
        sol_leaf.height,
        sol_leaf.cumulativeChainwork.to_be_bytes(),
    );
    let hash = core_leaf.hash::<Keccak256Hasher>();
    println!("{}", hex::encode(hash));
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    match args.command {
        Commands::GenerateFakeBlockMMRProof { height, debug } => {
            generate_fake_block_mmr_proof(height, debug).await;
        }
        Commands::GenerateFakeBlockWithConfirmationsMMRProof {
            height,
            confirmations,
            debug,
        } => {
            generate_fake_block_with_confirmations_mmr_proof(height, confirmations, debug).await;
        }
        Commands::HashBlockLeaf { abi_encoded_leaf } => {
            hash_block_leaf(&abi_encoded_leaf).await;
        }
    }
}
