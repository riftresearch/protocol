pub mod bindings;
pub mod bitcoin_utils;
mod errors;
pub mod mmr;
pub mod txn_builder;

use alloy::providers::{ProviderBuilder, WsConnect};
use alloy::pubsub::{ConnectionHandle, PubSubConnect};
use alloy::rpc::client::ClientBuilder;
use alloy::transports::{impl_future, TransportResult};
use alloy::{providers::Provider, pubsub::PubSubFrontend};
use backoff::exponential::ExponentialBackoff;
use bitcoin::hashes::hex::FromHex;
use rift_core::giga::RiftProgramInput;
use sp1_sdk::{include_elf, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};
use sp1_sdk::{EnvProver, HashableKey};
use sp1_sdk::{Prover, SP1ProvingKey};
use std::fmt::Write;
use std::str::FromStr;
use std::time::Instant;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const RIFT_PROGRAM_ELF: &[u8] = include_elf!("rift-program");

/// This is expensive to compute, so if you have a proof generator, use that instead.
pub fn get_rift_program_hash() -> [u8; 32] {
    let client = ProverClient::builder().mock().build();
    let (_, vk) = client.setup(RIFT_PROGRAM_ELF);
    vk.bytes32_raw()
}

pub fn load_hex_bytes(file: &str) -> Vec<u8> {
    let hex_string = std::fs::read_to_string(file).expect("Failed to read file");
    Vec::<u8>::from_hex(&hex_string).expect("Failed to parse hex")
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn get_retarget_height_from_block_height(block_height: u32) -> u32 {
    block_height - (block_height % 2016)
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Where to store the database (in-memory or on disk).
pub enum DatabaseLocation {
    InMemory,
    Directory(String),
}

impl FromStr for DatabaseLocation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "memory" => Ok(DatabaseLocation::InMemory),
            s => Ok(DatabaseLocation::Directory(s.to_string())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RetryWsConnect(WsConnect);

impl PubSubConnect for RetryWsConnect {
    fn is_local(&self) -> bool {
        self.0.is_local()
    }

    fn connect(&self) -> impl_future!(<Output = TransportResult<ConnectionHandle>>) {
        self.0.connect()
    }

    async fn try_reconnect(&self) -> TransportResult<ConnectionHandle> {
        backoff::future::retry(
            ExponentialBackoff::<backoff::SystemClock>::default(),
            || async { Ok(self.0.try_reconnect().await?) },
        )
        .await
    }
}

pub async fn create_websocket_provider(
    evm_rpc_websocket_url: &str,
) -> errors::Result<impl Provider<PubSubFrontend>> {
    let ws = RetryWsConnect(WsConnect::new(evm_rpc_websocket_url));
    let client = ClientBuilder::default()
        .pubsub(ws)
        .await
        .map_err(|e| errors::RiftSdkError::WebsocketProviderError(e.to_string()))?;

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_client(client);

    Ok(provider)
}

pub struct RiftProofGenerator {
    pub pk: SP1ProvingKey,
    pub vk: SP1VerifyingKey,
    pub circuit_verification_key_hash: [u8; 32],
    pub prover_type: ProofGeneratorType,
    pub prover_client: EnvProver,
}

impl RiftProofGenerator {
    /// Constructs a new `ProofGenerator` with the given prover type,
    /// sets up the SP1 environment, loads the proving/verifying keys,
    /// and stores the verification key hash.
    pub fn new(prover_type: ProofGeneratorType) -> Self {
        match prover_type {
            ProofGeneratorType::ProveCPU => {
                std::env::set_var("SP1_PROVER", "cpu");
            }
            ProofGeneratorType::ProveCUDA => {
                std::env::set_var("SP1_PROVER", "cuda");
            }
            ProofGeneratorType::ProveNetwork => {
                std::env::set_var("SP1_PROVER", "network");
            }
            ProofGeneratorType::Execute => {
                std::env::set_var("SP1_PROVER", "mock");
            }
        }

        let prover_client = ProverClient::from_env();
        let (pk, vk) = prover_client.setup(RIFT_PROGRAM_ELF);
        let circuit_verification_key_hash = vk.bytes32_raw();

        RiftProofGenerator {
            pk,
            vk,
            circuit_verification_key_hash,
            prover_type,
            prover_client,
        }
    }

    /// Executes or proves the program with the given configuration for the provided `RiftProgramInput`.
    /// This method now runs on a dedicated thread (using `spawn_blocking`) so it does not
    /// block the async executor's main threads.
    pub async fn prove(
        &self,
        input: &RiftProgramInput,
    ) -> Result<Proof, Box<dyn std::error::Error + Send + Sync>> {
        let pk = self.pk.clone();
        let vk = self.vk.clone();
        let circuit_verification_key_hash = self.circuit_verification_key_hash;
        let prover_type = self.prover_type;
        let prover_client = ProverClient::from_env();
        let input = input.clone();

        // Spawn a blocking task on the Tokio thread pool dedicated to blocking calls.
        let proof_result = tokio::task::spawn_blocking(move || {
            let start = Instant::now();

            // Prepare the SP1Stdin for the proving/execute call
            let mut stdin = SP1Stdin::new();
            stdin.write(&input);

            // Perform the CPU-intensive operation synchronously
            let proof_outcome = match prover_type {
                ProofGeneratorType::Execute => {
                    let (_output, report) =
                        prover_client.execute(RIFT_PROGRAM_ELF, &stdin).run()?;
                    Proof {
                        proof_type: ProofGeneratorType::Execute,
                        proof: None,
                        cycles: Some(report.total_instruction_count()),
                        duration: start.elapsed(),
                    }
                }
                ProofGeneratorType::ProveCPU
                | ProofGeneratorType::ProveCUDA
                | ProofGeneratorType::ProveNetwork => {
                    let sp1_proof = prover_client.prove(&pk, &stdin).groth16().run()?;
                    Proof {
                        proof_type: prover_type,
                        proof: Some(sp1_proof),
                        cycles: None,
                        duration: start.elapsed(),
                    }
                }
            };

            println!(
                "Completed {:?} in {}",
                proof_outcome.proof_type,
                format_duration(proof_outcome.duration)
            );

            Ok::<Proof, Box<dyn std::error::Error + Send + Sync>>(proof_outcome)
        })
        .await?; // first `?` handles JoinError from the spawned task

        // The returned value is `Result<Proof, Box<dyn std::error::Error + Send + Sync>>`
        proof_result
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofGeneratorType {
    Execute,
    ProveCPU,
    ProveCUDA,
    ProveNetwork,
}

#[derive(Debug)]
pub struct Proof {
    pub proof_type: ProofGeneratorType,
    pub proof: Option<SP1ProofWithPublicValues>,
    pub cycles: Option<u64>,
    pub duration: std::time::Duration,
}

/// Format a `Duration` for pretty printing in results.
pub fn format_duration(duration: std::time::Duration) -> String {
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
