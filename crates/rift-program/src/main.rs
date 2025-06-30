#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolValue;
use rift_core::giga::RiftProgramInput;

pub fn main() {
    // Read an input to the program.
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let circuit_input = sp1_zkvm::io::read::<RiftProgramInput>();

    // Verify the input and build the public input
    let public_input = circuit_input.verify().expect("Failed to prove input");

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&public_input.abi_encode());
}
