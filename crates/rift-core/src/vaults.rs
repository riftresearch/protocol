use alloy_sol_types::SolValue;
use sol_bindings::Order;
use tiny_keccak::{Hasher, Keccak};

pub trait SolidityHash {
    fn hash(&self) -> [u8; 32];
}

impl SolidityHash for Order {
    fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];

        let abi_encoded = Order::abi_encode(self);

        hasher.update(&abi_encoded);
        hasher.finalize(&mut output);
        output
    }
}
