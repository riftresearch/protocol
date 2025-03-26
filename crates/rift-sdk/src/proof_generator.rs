use crate::RIFT_PROGRAM_ELF;
use rift_core::giga::RiftProgramInput;
use sp1_sdk::{
    include_elf, EnvProver, HashableKey, Prover, ProverClient, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

pub struct RiftProofGenerator {
    pub pk: Arc<SP1ProvingKey>,
    pub vk: Arc<SP1VerifyingKey>,
    pub prover_client: Arc<EnvProver>,
    pub circuit_verification_key_hash: [u8; 32],
    pub prover_type: ProofGeneratorType,
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
            pk: Arc::new(pk),
            vk: Arc::new(vk),
            circuit_verification_key_hash,
            prover_type,
            prover_client: Arc::new(prover_client),
        }
    }

    /// Executes or proves the program with the given configuration for the provided `RiftProgramInput`.
    /// This method now runs on a dedicated thread (using `spawn_blocking`) so it does not
    /// block the async executor's main threads.
    /// TODO: Consider if we should use a queue/channel to limit the number of concurrent proofs
    pub async fn prove(
        &self,
        input: &RiftProgramInput,
    ) -> Result<Proof, Box<dyn std::error::Error + Send + Sync>> {
        let pk = self.pk.clone();
        let prover_type = self.prover_type;
        let prover_client = self.prover_client.clone();

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

impl FromStr for ProofGeneratorType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "execute" => Ok(Self::Execute),
            "prove-cpu" => Ok(Self::ProveCPU),
            "prove-cuda" => Ok(Self::ProveCUDA),
            "prove-network" => Ok(Self::ProveNetwork),
            _ => Err("Invalid proof generator type. Must be 'execute', 'prove-cpu', 'prove-cuda', or 'prove-network'".to_string()),
        }
    }
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
