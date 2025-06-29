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
use rift_sdk::indexed_mmr::IndexedMMR;
use rift_sdk::proof_generator::{format_duration, Proof, ProofGeneratorType, RiftProofGenerator};
use rift_sdk::DatabaseLocation;

use test_data_utils::{EXHAUSTIVE_TEST_HEADERS, TEST_BCH_HEADERS};

use bitcoin_light_client_core::hasher::{Digest, Keccak256Hasher};
use bitcoin_light_client_core::leaves::{create_new_leaves, get_genesis_leaf, BlockLeaf};
use bitcoin_light_client_core::light_client::Header;

use bitcoin_light_client_core::mmr::MMRProof;
use bitcoin_light_client_core::{validate_chainwork, ChainTransition, ProvenLeaf, VerifiedBlock};

use accumulators::mmr::element_index_to_leaf_index;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Type of prover to use: "execute", "gas", "cpu", "cuda", or "network"
    #[arg(short, long, default_value = "execute")]
    prover: String,

    /// Number of samples to average for each block count
    #[arg(long, default_value_t = 1)]
    samples: usize,
}

/// Holds a "circuit MMR" (used for building the final root) and a "client MMR" (for real proofs),
/// plus metadata about the chain at block #478558.
struct BchOverwriteMMRState {
    indexed_mmr: IndexedMMR<Keccak256Hasher>, // used to fetch real proofs
    base_leaf_index: usize,

    /// Mapping height -> element_index in the client MMR
    height_to_index: HashMap<u32, usize>,
    base_height_to_index: HashMap<u32, usize>,

    /// parent data
    parent_header: Header,
    parent_leaf: BlockLeaf,
    parent_element_index: usize,

    /// retarget data
    parent_retarget_header: Header,
    parent_retarget_leaf: BlockLeaf,
    parent_retarget_element_index: usize,

    /// MMR root/bagged peak right after 478558
    _pre_bch_mmr_root: Digest,
    _pre_bch_mmr_bagged_peak: Digest,
    pre_bch_peaks: Vec<Digest>,
}

/// Build an MMR up to #478558 (inclusive), storing real client MMR indexes.
impl BchOverwriteMMRState {
    async fn new() -> Self {
        println!("Building initial MMR state up to block #478558...");
        let start = Instant::now();

        // 1) Genesis
        let genesis_leaf = get_genesis_leaf();

        // 2) Create both MMRs:

        let mut indexed_mmr = IndexedMMR::<Keccak256Hasher>::open(&DatabaseLocation::InMemory)
            .await
            .unwrap();
        let append_result = indexed_mmr.append(&genesis_leaf).await.unwrap();
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

        for leaf in leaves.iter() {
            let result = indexed_mmr
                .append(leaf)
                .await
                .expect("Failed to append leaf to client MMR");
            height_to_index.insert(leaf.height, result.element_index);
        }

        let pre_bch_mmr_root = indexed_mmr.get_root().await.unwrap();
        let pre_bch_mmr_bagged_peak = indexed_mmr.get_bagged_peak().await.unwrap();
        let pre_bch_peaks = indexed_mmr.get_peaks(None).await.unwrap();

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

        let base_height_to_index = height_to_index.clone();
        let base_leaf_index = indexed_mmr.get_leaf_count().await.unwrap() - 1;

        Self {
            indexed_mmr,
            height_to_index,
            parent_header,
            parent_leaf,
            parent_element_index,
            parent_retarget_header,
            parent_retarget_leaf,
            parent_retarget_element_index,
            _pre_bch_mmr_root: pre_bch_mmr_root,
            _pre_bch_mmr_bagged_peak: pre_bch_mmr_bagged_peak,
            pre_bch_peaks,
            base_height_to_index,
            base_leaf_index,
        }
    }

    async fn reset_to_base(&mut self) {
        println!("Resetting to base chain state...");

        let start = Instant::now();

        self.indexed_mmr.rewind(self.base_leaf_index).await.unwrap();
        self.height_to_index = self.base_height_to_index.clone();

        println!("Reset to base in {}", format_duration(start.elapsed()));
    }
}

/// Append `n` BCH blocks, returning the new tip's leaf/header + real MMR proof
async fn extend_with_bch_blocks(
    state: &mut BchOverwriteMMRState,
    n: usize,
) -> (BlockLeaf, Header, MMRProof, Vec<BlockLeaf>) {
    println!("Extending chain with {} disposed blocks...", n);
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
        let res = state.indexed_mmr.append(leaf).await.unwrap();
        state.height_to_index.insert(leaf.height, res.element_index);
    }

    // the new tip
    let current_tip_leaf = *bch_leaves.last().unwrap();
    let current_tip_header = bch_headers.last().unwrap();
    let current_tip_element_index = *state.height_to_index.get(&current_tip_leaf.height).unwrap();

    let current_tip_leaf_index = element_index_to_leaf_index(current_tip_element_index).unwrap();

    // real mmr proof
    let current_tip_proof = state
        .indexed_mmr
        .get_circuit_proof(current_tip_leaf_index, None)
        .await
        .unwrap();

    println!("Chain extended in {}", format_duration(start.elapsed()));
    (
        current_tip_leaf,
        *current_tip_header,
        current_tip_proof,
        bch_leaves,
    )
}

/// Build a single chain transition that disposes of `n` BCH blocks and appends `n+1` BTC blocks.
async fn create_bch_overwrite_chain_transition(
    state: &mut BchOverwriteMMRState,
    n: usize,
) -> ChainTransition {
    println!("Creating chain transition...");
    let start = Instant::now();

    // 1) Append n BCH blocks
    let (current_tip_leaf, _current_tip_header, current_tip_proof, bch_leaves) =
        extend_with_bch_blocks(state, n).await;

    // 2) Collect their leaf hashes (to "dispose" them)
    let disposed_leaf_hashes = bch_leaves
        .iter()
        .map(|l| l.hash::<Keccak256Hasher>())
        .collect::<Vec<_>>();

    // 3) We now fetch real proofs for the parent and parent_retarget as well
    //    (they were set in BchOverwriteMMRState).

    let parent_leaf_index = element_index_to_leaf_index(state.parent_element_index).unwrap();
    let parent_inclusion_proof = state
        .indexed_mmr
        .get_circuit_proof(parent_leaf_index, None)
        .await
        .unwrap();

    let parent_retarget_leaf_index =
        element_index_to_leaf_index(state.parent_retarget_element_index).unwrap();
    let parent_retarget_inclusion_proof = state
        .indexed_mmr
        .get_circuit_proof(parent_retarget_leaf_index, None)
        .await
        .unwrap();

    // 4) The previous MMR root is the chain after we appended n BCH blocks
    let current_mmr_root = state.indexed_mmr.get_root().await.unwrap();
    let current_mmr_bagged_peak = state.indexed_mmr.get_bagged_peak().await.unwrap();

    // 5) Next gather n+1 BTC headers
    let start_idx = 478559;
    let end_idx = (start_idx + n + 1).min(EXHAUSTIVE_TEST_HEADERS.len());
    let btc_headers = EXHAUSTIVE_TEST_HEADERS[start_idx..end_idx]
        .iter()
        .map(|(_, h)| Header(*h))
        .collect::<Vec<_>>();

    // 6) The "previous tip" proof is the proof we just got for the last BCH block
    //    (current_tip_leaf & current_tip_proof).

    // 7) Build the chain transition
    let chain_transition = ChainTransition {
        current_mmr_root,
        current_mmr_bagged_peak,
        parent: VerifiedBlock {
            header: state.parent_header,
            mmr_data: ProvenLeaf {
                leaf: state.parent_leaf,
                proof: parent_inclusion_proof,
            },
        },
        parent_retarget: VerifiedBlock {
            header: state.parent_retarget_header,
            mmr_data: ProvenLeaf {
                leaf: state.parent_retarget_leaf,
                proof: parent_retarget_inclusion_proof,
            },
        },
        current_tip: ProvenLeaf {
            leaf: current_tip_leaf,
            proof: current_tip_proof,
        },
        parent_leaf_peaks: state.pre_bch_peaks.clone(),
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
async fn prove_chain_transition(
    chain_transition: ChainTransition,
    benchmark_type: ProofGeneratorType,
    proof_generator: &RiftProofGenerator,
) -> Proof {
    println!("Starting {:?} for chain transition...", benchmark_type);

    let program_input = rift_core::giga::RiftProgramInput::builder()
        .proof_type(rift_core::giga::RustProofType::LightClientOnly)
        .light_client_input(chain_transition)
        .build()
        .unwrap();

    proof_generator.prove(&program_input).await.unwrap()
}

/// Runs the entire "dispose n BCH blocks and append n+1 BTC blocks" scenario with real MMR proofs.
async fn prove_bch_overwrite(
    n: usize,
    base_state: &mut BchOverwriteMMRState,
    benchmark_type: ProofGeneratorType,
    proof_generator: &RiftProofGenerator,
) -> Proof {
    // 1) Create a single chain transition that disposes of `n` BCH blocks and appends `n+1` BTC blocks
    let chain_transition = create_bch_overwrite_chain_transition(base_state, n).await;

    // 3) Execute or prove
    prove_chain_transition(chain_transition, benchmark_type, proof_generator).await
}

fn average_and_std(values: &[f64]) -> (f64, f64) {
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    if values.len() < 2 {
        return (mean, 0.0);
    }
    let variance = values.iter().map(|v| (*v - mean).powi(2)).sum::<f64>() / n;
    (mean, variance.sqrt())
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let args = Args::parse();
    let benchmark_type = match args.prover.to_lowercase().as_str() {
        "execute" => ProofGeneratorType::Execute,
        "gas" => ProofGeneratorType::Gas,
        "cpu" => ProofGeneratorType::ProveCPU,
        "cuda" => ProofGeneratorType::ProveCUDA,
        "network" => ProofGeneratorType::ProveNetwork,
        _ => panic!("Invalid prover type. Must be 'execute', 'cpu', 'cuda', or 'network'"),
    };

    let mut table = Table::new();
    if matches!(benchmark_type, ProofGeneratorType::Execute) {
        if args.samples > 1 {
            table.add_row(row![
                "Disposed Blocks",
                "Avg Cycles",
                "Cycle Std Dev",
                "Avg Time",
                "Time Std Dev"
            ]);
        } else {
            table.add_row(row!["Disposed Blocks", "Cycle Count", "Time"]);
        }
    } else if matches!(benchmark_type, ProofGeneratorType::Gas) {
        if args.samples > 1 {
            table.add_row(row![
                "Disposed Blocks",
                "Avg Gas",
                "Gas Std Dev",
                "Avg Time",
                "Time Std Dev"
            ]);
        } else {
            table.add_row(row!["Disposed Blocks", "Gas", "Time"]);
        }
    } else if args.samples > 1 {
        table.add_row(row!["Disposed Blocks", "Avg Time", "Time Std Dev"]);
    } else {
        table.add_row(row!["Disposed Blocks", "Time to Prove"]);
    }

    let proof_generator = RiftProofGenerator::new(benchmark_type);

    println!("Initializing base state (syncing 478558 BCH blocks)...");
    let start = Instant::now();
    let mut base_state = BchOverwriteMMRState::new().await;
    println!(
        "Base state initialized in {}",
        format_duration(start.elapsed())
    );

    let mut regression_data: Vec<(f64, f64)> = Vec::new();
    for &n in &[1, 6, 24, 144, 288, 576, 1008, 2016] {
        println!("=== Overwriting {n} BCH blocks with {n}+1 BTC blocks ===");

        let mut durations = Vec::new();
        let mut cycles_vec = Vec::new();
        let mut gas_vec = Vec::new();
        for _ in 0..args.samples {
            let result =
                prove_bch_overwrite(n, &mut base_state, benchmark_type, &proof_generator).await;
            durations.push(result.duration.as_secs_f64());
            if let Some(c) = result.cycles {
                cycles_vec.push(c as f64);
            }
            if let Some(g) = result.gas {
                gas_vec.push(g as f64);
            }

            // reset the state so we can run the next benchmark
            base_state.reset_to_base().await;
        }

        let (avg_duration, std_duration) = average_and_std(&durations);
        if !cycles_vec.is_empty() {
            let (avg_cycles, std_cycles) = average_and_std(&cycles_vec);
            if args.samples > 1 {
                table.add_row(row![
                    n,
                    avg_cycles as u64,
                    format!("{:.2}", std_cycles),
                    format_duration(std::time::Duration::from_secs_f64(avg_duration)),
                    format_duration(std::time::Duration::from_secs_f64(std_duration)),
                ]);
            } else {
                table.add_row(row![
                    n,
                    avg_cycles as u64,
                    format_duration(std::time::Duration::from_secs_f64(avg_duration))
                ]);
            }
        } else if !gas_vec.is_empty() {
            let (avg_gas, std_gas) = average_and_std(&gas_vec);
            if args.samples > 1 {
                table.add_row(row![
                    n,
                    avg_gas as u64,
                    format!("{:.2}", std_gas),
                    format_duration(std::time::Duration::from_secs_f64(avg_duration)),
                    format_duration(std::time::Duration::from_secs_f64(std_duration)),
                ]);
            } else {
                table.add_row(row![
                    n,
                    avg_gas as u64,
                    format_duration(std::time::Duration::from_secs_f64(avg_duration))
                ]);
            }
        } else if args.samples > 1 {
            table.add_row(row![
                n,
                format_duration(std::time::Duration::from_secs_f64(avg_duration)),
                format_duration(std::time::Duration::from_secs_f64(std_duration)),
            ]);
        } else {
            table.add_row(row![
                n,
                format_duration(std::time::Duration::from_secs_f64(avg_duration)),
            ]);
        }

        regression_data.push((n as f64, avg_duration));
    }

    table.printstd();

    if regression_data.len() > 1 {
        let count = regression_data.len() as f64;
        let sum_x: f64 = regression_data.iter().map(|(x, _)| *x).sum();
        let sum_y: f64 = regression_data.iter().map(|(_, y)| *y).sum();
        let mean_x = sum_x / count;
        let mean_y = sum_y / count;

        let mut numerator = 0.0;
        let mut denominator = 0.0;
        for (x, y) in regression_data.iter() {
            numerator += (*x - mean_x) * (*y - mean_y);
            denominator += (*x - mean_x).powi(2);
        }

        let slope = numerator / denominator;
        let intercept = mean_y - slope * mean_x;

        let mut ss_res = 0.0;
        let mut ss_tot = 0.0;
        for (x, y) in regression_data.iter() {
            let predicted = slope * *x + intercept;
            ss_res += (*y - predicted).powi(2);
            ss_tot += (*y - mean_y).powi(2);
        }

        let r_squared = 1.0 - ss_res / ss_tot;

        println!(
            "Linear regression: proof time as a function of blocks disposed + appended:\ny = {:.4} x + {:.4};  R² = {:.4}",
            slope, intercept, r_squared
        );
    }
}
