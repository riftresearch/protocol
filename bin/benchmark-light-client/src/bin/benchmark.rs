//! benchmark.rs
//!
//! Benchmark the cycle count of the btc-light-client program (proxied through rift-program) for various numbers of blocks.
//! This also demonstrates a "worst-case" scenario: appending `n` fake blocks, then disposing
//! of those `n` blocks to overwrite them with `n+1` blocks in a single chain transition.
//!
use std::collections::HashMap;
use std::time::Instant;

use clap::Parser;
use prettytable::{row, Table};
use tokio::runtime::Runtime;

use sp1_sdk::{include_elf, ProverClient, SP1ProvingKey, SP1Stdin};
use test_data_utils::{EXHAUSTIVE_TEST_HEADERS, TEST_BCH_HEADERS};

use bitcoin_light_client_core::hasher::{Digest, Hasher, Keccak256Hasher};
use bitcoin_light_client_core::leaves::{create_new_leaves, get_genesis_leaf, BlockLeaf};
use bitcoin_light_client_core::light_client::Header;

use bitcoin_light_client_core::mmr::{CompactMerkleMountainRange, MMRProof};
use bitcoin_light_client_core::{validate_chainwork, BlockPosition, ChainTransition};

pub const RIFT_PROGRAM_ELF: &[u8] = include_elf!("rift-program");

use accumulators::mmr::{
    element_index_to_leaf_index, elements_count_to_leaf_count, Proof as ClientMMRProof,
};
use accumulators::{
    hasher::keccak::KeccakHasher as ClientKeccakHasher, mmr::MMR as ClientMMR,
    store::memory::InMemoryStore,
};

use std::sync::Arc;

pub fn digest_to_hex(digest: &Digest) -> String {
    format!("0x{}", hex::encode(digest))
}

pub fn client_mmr_proof_to_minimal_mmr_proof(proof: &ClientMMRProof) -> MMRProof {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BenchmarkType {
    Execute,
    ProveLocal,
    ProveNetwork,
}

#[derive(Debug)]
struct BenchmarkResult {
    cycles: Option<u64>,
    duration: std::time::Duration,
}

/// Format a `Duration` for pretty printing in results.
fn format_duration(duration: std::time::Duration) -> String {
    if duration.as_secs() == 0 {
        return format!("{} ms", duration.as_millis());
    }
    if duration.as_secs() < 60 {
        return format!("{:.2} s", duration.as_secs_f64());
    }
    if duration.as_secs() < 3600 {
        return format!("{:.2} min", duration.as_secs_f64() / 60.0);
    }
    format!("{:.2} h", duration.as_secs_f64() / 3600.0)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The type of benchmark to run: "execute", "prove-local", or "prove-network"
    #[arg(short, long, default_value = "execute")]
    r#type: String,
}

/// Holds a “circuit MMR” (used for building the final root) and a “client MMR” (for real proofs),
/// plus metadata about the chain at block #478558.
struct BchOverwriteMMRState {
    circuit_mmr: CompactMerkleMountainRange<Keccak256Hasher>,
    client_mmr: ClientMMR, // used to fetch real proofs

    /// Mapping height -> element_index in the client MMR
    height_to_index: HashMap<u32, usize>,

    /// parent data
    parent_header: Header,
    parent_leaf: BlockLeaf,
    parent_element_index: usize,

    /// retarget data
    parent_retarget_header: Header,
    parent_retarget_leaf: BlockLeaf,
    parent_retarget_element_index: usize,

    /// MMR root/bagged peak right after 478558
    pre_bch_mmr_root: Digest,
    pre_bch_mmr_bagged_peak: Digest,
    pre_bch_peaks: Vec<Digest>,
}

/// Build an MMR up to #478558 (inclusive), storing real client MMR indexes.
impl BchOverwriteMMRState {
    async fn new() -> Self {
        println!("Building initial MMR state up to block #478558...");
        let start = Instant::now();

        // 1) Genesis
        let genesis_leaf = get_genesis_leaf();
        let genesis_leaf_hash = genesis_leaf.hash::<Keccak256Hasher>();

        // 2) Create both MMRs:
        let mut circuit_mmr = CompactMerkleMountainRange::<Keccak256Hasher>::new();
        circuit_mmr.append(&genesis_leaf_hash);

        let mut client_mmr = create_keccak256_client_mmr();
        let append_result = client_mmr
            .append(digest_to_hex(&genesis_leaf_hash))
            .await
            .unwrap();
        let mut height_to_index = HashMap::new();
        height_to_index.insert(genesis_leaf.height, append_result.element_index);

        // 3) Append all mainnet headers up to block 478558
        println!("Appending mainnet headers...");
        let headers = EXHAUSTIVE_TEST_HEADERS[1..=478558]
            .iter()
            .map(|(_, h)| Header(*h))
            .collect::<Vec<_>>();

        let (chain_works, _) = validate_chainwork(&genesis_leaf, &genesis_leaf, &headers);
        let leaves = create_new_leaves(&genesis_leaf, &headers, &chain_works);

        for (i, leaf) in leaves.iter().enumerate() {
            let leaf_hash = leaf.hash::<Keccak256Hasher>();
            circuit_mmr.append(&leaf_hash);

            let result = client_mmr
                .append(digest_to_hex(&leaf_hash))
                .await
                .expect("Failed to append leaf to client MMR");
            height_to_index.insert(leaf.height, result.element_index);
        }

        let pre_bch_mmr_root = circuit_mmr.get_root();
        let pre_bch_mmr_bagged_peak = circuit_mmr.bag_peaks().unwrap();
        let pre_bch_peaks = circuit_mmr.peaks.clone();

        // The parent is block #478558
        let parent_leaf = *leaves.last().unwrap();
        let parent_header = *headers.last().unwrap();
        let parent_element_index = *height_to_index
            .get(&parent_leaf.height)
            .expect("No index found for parent");

        // The parent retarget block
        let parent_retarget_height =
            bitcoin_core_rs::get_retarget_height(parent_leaf.height) as u32;
        let parent_retarget_leaf = *leaves
            .iter()
            .find(|l| l.height == parent_retarget_height)
            .unwrap();

        let parent_retarget_header = headers[parent_retarget_height as usize - 1];

        let parent_retarget_element_index = *height_to_index
            .get(&parent_retarget_height)
            .expect("No index for parent retarget height");

        // done
        println!(
            "Initial MMR state built in {}",
            format_duration(start.elapsed())
        );
        Self {
            circuit_mmr,
            client_mmr,
            height_to_index,
            parent_header,
            parent_leaf,
            parent_element_index,
            parent_retarget_header,
            parent_retarget_leaf,
            parent_retarget_element_index,
            pre_bch_mmr_root,
            pre_bch_mmr_bagged_peak,
            pre_bch_peaks,
        }
    }
}

/// Append `n` BCH blocks, returning the new tip's leaf/header + real MMR proof
async fn extend_with_bch_blocks(
    state: &mut BchOverwriteMMRState,
    n: usize,
) -> (BlockLeaf, Header, MMRProof, Vec<BlockLeaf>) {
    println!("Extending chain with {} BCH blocks...", n);
    let start = Instant::now();

    let parent_leaf = state.parent_leaf;
    let bch_headers = TEST_BCH_HEADERS[..n.min(TEST_BCH_HEADERS.len())]
        .iter()
        .map(|(_, h)| Header(*h))
        .collect::<Vec<_>>();

    // chainwork and leaves
    let (chain_works, _) = validate_chainwork(&parent_leaf, &parent_leaf, &bch_headers);
    let bch_leaves = create_new_leaves(&parent_leaf, &bch_headers, &chain_works);

    // append them
    for leaf in bch_leaves.iter() {
        let leaf_hash = leaf.hash::<Keccak256Hasher>();
        state.circuit_mmr.append(&leaf_hash);
        let res = state
            .client_mmr
            .append(digest_to_hex(&leaf_hash))
            .await
            .unwrap();
        state.height_to_index.insert(leaf.height, res.element_index);
    }

    // the new tip
    let previous_tip_leaf = *bch_leaves.last().unwrap();
    let previous_tip_header = bch_headers.last().unwrap().clone();
    let previous_tip_element_index = *state
        .height_to_index
        .get(&previous_tip_leaf.height)
        .unwrap();

    // real mmr proof
    let proof = state
        .client_mmr
        .get_proof(previous_tip_element_index, None)
        .await
        .unwrap();
    let previous_tip_proof = client_mmr_proof_to_minimal_mmr_proof(&proof);

    println!("Chain extended in {}", format_duration(start.elapsed()));
    (
        previous_tip_leaf,
        previous_tip_header,
        previous_tip_proof,
        bch_leaves,
    )
}

/// Build a single chain transition that disposes of `n` BCH blocks and appends `n+1` BTC blocks.
async fn create_bch_overwrite_chain_transition(
    mut state: BchOverwriteMMRState,
    n: usize,
) -> ChainTransition {
    println!("Creating chain transition...");
    let start = Instant::now();

    // 1) Append n BCH blocks
    let (previous_tip_leaf, previous_tip_header, previous_tip_proof, bch_leaves) =
        extend_with_bch_blocks(&mut state, n).await;

    // 2) Collect their leaf hashes (to "dispose" them)
    let disposed_leaf_hashes = bch_leaves
        .iter()
        .map(|l| l.hash::<Keccak256Hasher>())
        .collect::<Vec<_>>();

    // 3) We now fetch real proofs for the parent and parent_retarget as well
    //    (they were set in BchOverwriteMMRState).
    let parent_proof_raw = state
        .client_mmr
        .get_proof(state.parent_element_index, None)
        .await
        .unwrap();
    let parent_inclusion_proof = client_mmr_proof_to_minimal_mmr_proof(&parent_proof_raw);

    let parent_retarget_proof_raw = state
        .client_mmr
        .get_proof(state.parent_retarget_element_index, None)
        .await
        .unwrap();
    let parent_retarget_inclusion_proof =
        client_mmr_proof_to_minimal_mmr_proof(&parent_retarget_proof_raw);

    // 4) The previous MMR root is the chain after we appended n BCH blocks
    let previous_mmr_root = state.circuit_mmr.get_root();
    let previous_mmr_bagged_peak = state.circuit_mmr.bag_peaks().unwrap();

    // 5) Next gather n+1 BTC headers
    let start_idx = 478559;
    let end_idx = (start_idx + n + 1).min(EXHAUSTIVE_TEST_HEADERS.len());
    let btc_headers = EXHAUSTIVE_TEST_HEADERS[start_idx..end_idx]
        .iter()
        .map(|(_, h)| Header(*h))
        .collect::<Vec<_>>();

    // 6) The "previous tip" proof is the proof we just got for the last BCH block
    //    (previous_tip_leaf & previous_tip_proof).

    // 7) Build the chain transition
    let chain_transition = ChainTransition {
        previous_mmr_root,
        previous_mmr_bagged_peak,
        parent: BlockPosition {
            header: state.parent_header.clone(),
            leaf: state.parent_leaf,
            inclusion_proof: parent_inclusion_proof,
        },
        parent_retarget: BlockPosition {
            header: state.parent_retarget_header.clone(),
            leaf: state.parent_retarget_leaf,
            inclusion_proof: parent_retarget_inclusion_proof,
        },
        previous_tip: BlockPosition {
            header: previous_tip_header,
            leaf: previous_tip_leaf,
            inclusion_proof: previous_tip_proof,
        },
        parent_leaf_peaks: state.pre_bch_peaks,
        disposed_leaf_hashes,
        new_headers: btc_headers,
    };

    println!(
        "Chain transition created in {}",
        format_duration(start.elapsed())
    );
    chain_transition
}

/// Actually prove or execute the chain transition in the RIFT VM
fn prove_chain_transition(
    chain_transition: ChainTransition,
    benchmark_type: BenchmarkType,
    prover_client: &ProverClient,
    proving_key: &SP1ProvingKey,
) -> BenchmarkResult {
    println!("Starting {:?} for chain transition...", benchmark_type);
    let start = Instant::now();

    // Setup the SP1 prover environment
    match benchmark_type {
        BenchmarkType::ProveNetwork => std::env::set_var("SP1_PROVER", "network"),
        BenchmarkType::ProveLocal => std::env::set_var("SP1_PROVER", "local"),
        BenchmarkType::Execute => std::env::set_var("SP1_PROVER", "mock"),
    }

    let program_input = rift_core::giga::RiftProgramInput::builder()
        .proof_type(rift_core::giga::ProofType::LightClient)
        .light_client_input(chain_transition)
        .build()
        .unwrap();

    let mut stdin = SP1Stdin::new();
    stdin.write(&program_input);

    match benchmark_type {
        BenchmarkType::Execute => {
            let (_output, report) = prover_client
                .execute(RIFT_PROGRAM_ELF, stdin)
                .run()
                .unwrap();
            let duration = start.elapsed();
            let result = BenchmarkResult {
                cycles: Some(report.total_instruction_count()),
                duration,
            };
            println!(
                "Completed {:?} in {}",
                benchmark_type,
                format_duration(result.duration)
            );
            result
        }
        BenchmarkType::ProveLocal | BenchmarkType::ProveNetwork => {
            prover_client
                .prove(&proving_key, stdin)
                .groth16()
                .run()
                .unwrap();
            let duration = start.elapsed();
            let result = BenchmarkResult {
                cycles: None,
                duration,
            };
            println!(
                "Completed {:?} in {}",
                benchmark_type,
                format_duration(result.duration)
            );
            result
        }
    }
}

/// Runs the entire “dispose n BCH blocks and append n+1 BTC blocks” scenario with real MMR proofs.
async fn prove_bch_overwrite(
    n: usize,
    benchmark_type: BenchmarkType,
    prover_client: &ProverClient,
    proving_key: &SP1ProvingKey,
) -> BenchmarkResult {
    // 1) Build the chain (and client MMR) up to block 478558
    let state = BchOverwriteMMRState::new().await;

    // 2) Create a single chain transition that disposes of `n` BCH blocks and appends `n+1` BTC blocks
    let chain_transition = create_bch_overwrite_chain_transition(state, n).await;

    // 3) Execute or prove
    prove_chain_transition(chain_transition, benchmark_type, prover_client, proving_key)
}

// Optionally, you could also add a simpler “extend from genesis” scenario or others.

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let args = Args::parse();
    let benchmark_type = match args.r#type.to_lowercase().as_str() {
        "execute" => BenchmarkType::Execute,
        "prove-local" => BenchmarkType::ProveLocal,
        "prove-network" => BenchmarkType::ProveNetwork,
        _ => panic!("Invalid benchmark type. Must be 'execute', 'prove-local', or 'prove-network'"),
    };

    let mut table = Table::new();
    if matches!(benchmark_type, BenchmarkType::Execute) {
        table.add_row(row!["n (BCH blocks)", "Cycle Count", "Time"]);
    } else {
        table.add_row(row!["n (BCH blocks)", "Time to Prove"]);
    }

    match benchmark_type {
        BenchmarkType::ProveLocal => {
            std::env::set_var("SP1_PROVER", "local");
        }
        BenchmarkType::ProveNetwork => {
            std::env::set_var("SP1_PROVER", "network");
        }
        BenchmarkType::Execute => {
            std::env::set_var("SP1_PROVER", "mock");
        }
    }

    let prover_client = ProverClient::new();
    let (pk, _vk) = prover_client.setup(RIFT_PROGRAM_ELF);

    for &n in &[1, 5, 10, 50, 100, 500, 1_000, 10_000] {
        println!("=== Overwriting {n} BCH blocks with {n}+1 BTC blocks ===");
        let result = prove_bch_overwrite(n, benchmark_type, &prover_client, &pk).await;
        println!("Result: {:?}", result);

        if let Some(cycles) = result.cycles {
            table.add_row(row![n, cycles, format_duration(result.duration)]);
        } else {
            table.add_row(row![n, format_duration(result.duration)]);
        }
    }

    table.printstd();
}
