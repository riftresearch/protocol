use bitcoin::consensus::encode::deserialize;
use bitcoin::Transaction;
use tiny_keccak::{Hasher, Keccak};

use sol_bindings::Order;

use crate::order_hasher::SolidityHash;

// Constants
pub const OP_RETURN_CODE: u8 = 0x6a;
pub const OP_PUSHBYTES_32: u8 = 0x20;

pub trait AggregateOrderHasher {
    fn compute_aggregate_hash(&self) -> [u8; 32];
}

impl<I> AggregateOrderHasher for I
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
    for<'a> &'a I: IntoIterator<Item = &'a I::Item>,
{
    fn compute_aggregate_hash(&self) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        for h in self {
            hasher.update(h.as_ref());
        }
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        out
    }
}

/// A Rift Order filling transaction is a bitcoin transaction that has a very specific structure:
/// *arbitrary number of inputs*
/// outputs:
/// n: index of the OP_RETURN in the tx
/// 0..n-1: payment outputs in the order the orders are being passed.
///     - For each payment output, the value and script pubkey are validated against the expected sats and script pubkey
/// n: OP_RETURN storing the aggregate order hash: keccak256(orders.fold(b"", |acc, order| acc + order.hash()))
pub fn validate_bitcoin_payments(
    txn_data: &[u8],
    orders: &[Order],
    op_return_index: usize,
) -> Result<Vec<[u8; 32]>, &'static str> {
    // [0] deserialize txn data
    let transaction: Transaction =
        deserialize(txn_data).map_err(|_| "Failed to deserialize transaction")?;

    // [1] Ensure orders length and op_return index are all valid for this transaction
    if orders.is_empty() {
        return Err("No orders to validate");
    }

    if orders.len() != op_return_index {
        return Err("Number of orders doesn't match the number of payment outputs");
    }

    let output_counter = transaction.output.len();
    if output_counter < (op_return_index + 1) {
        return Err("Transaction doesn't have enough outputs");
    }
    let payment_outputs = &transaction.output[0..op_return_index];

    // interleave orders and payment outputs, and check each pair
    for (order, payment_output) in orders.iter().zip(payment_outputs.iter()) {
        // [3] check payment output value matches order specified expected sats
        if payment_output.value.to_sat() != order.expectedSats {
            return Err("Transaction output value doesn't match expected sats");
        }

        // [4] check payment output script pubkey matches order specified wallet
        if payment_output.script_pubkey.as_bytes() != order.bitcoinScriptPubKey.to_vec() {
            return Err("Transaction recipient doesn't match LP wallet");
        }
    }

    let all_order_hashes = orders.iter().map(|order| order.hash()).collect::<Vec<_>>();
    let aggregate_order_hash = all_order_hashes.compute_aggregate_hash();

    // [5] check that the OP_RETURN inscribed aggregate order hash matches the computed aggregate order hash
    let op_return_output = &transaction.output[op_return_index];
    let op_return_script_pubkey = op_return_output.script_pubkey.as_bytes();

    if op_return_script_pubkey.len() < 34 {
        return Err("OP_RETURN output script is too short");
    }

    if op_return_script_pubkey[0] != OP_RETURN_CODE {
        return Err("Second output is not an OP_RETURN");
    }

    if op_return_script_pubkey[1] != OP_PUSHBYTES_32 {
        return Err("OP_RETURN output is not pushing 32 bytes");
    }

    let inscribed_aggregate_order_hash = &op_return_script_pubkey[2..34];

    if inscribed_aggregate_order_hash != aggregate_order_hash {
        return Err("Inscribed aggregate order hash doesn't match computed aggregate order hash");
    }

    Ok(all_order_hashes)
}
