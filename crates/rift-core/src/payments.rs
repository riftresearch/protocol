use bitcoin::consensus::encode::deserialize;
use bitcoin::Transaction;
use snafu::prelude::*;
use tiny_keccak::{Hasher, Keccak};

use sol_bindings::Order;

use crate::error::{
    PaymentValidationFailed, Result, TransactionDeserializationFailed,
};
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
) -> Result<Vec<[u8; 32]>> {
    // [0] deserialize txn data
    let transaction: Transaction =
        deserialize(txn_data).map_err(|e| TransactionDeserializationFailed {
            txn_bytes: txn_data.to_vec(),
            source: e,
        }.build())?;

    // [1] Ensure orders length and op_return index are all valid for this transaction
    ensure!(
        !orders.is_empty(),
        PaymentValidationFailed {
            reason: "No orders to validate".to_string()
        }
    );

    ensure!(
        orders.len() == op_return_index,
        PaymentValidationFailed {
            reason: "Number of orders doesn't match the number of payment outputs".to_string()
        }
    );

    let output_counter = transaction.output.len();
    ensure!(
        output_counter >= (op_return_index + 1),
        PaymentValidationFailed {
            reason: "Transaction doesn't have enough outputs".to_string()
        }
    );
    let payment_outputs = &transaction.output[0..op_return_index];

    // interleave orders and payment outputs, and check each pair
    for (order, payment_output) in orders.iter().zip(payment_outputs.iter()) {
        // [3] check payment output value matches order specified expected sats
        ensure!(
            payment_output.value.to_sat() == order.expectedSats,
            PaymentValidationFailed {
                reason: "Transaction output value doesn't match expected sats".to_string()
            }
        );

        // [4] check payment output script pubkey matches order specified wallet
        ensure!(
            payment_output.script_pubkey.as_bytes() == order.bitcoinScriptPubKey.to_vec(),
            PaymentValidationFailed {
                reason: "Transaction recipient doesn't match LP wallet".to_string()
            }
        );
    }

    let all_order_hashes = orders.iter().map(|order| order.hash()).collect::<Vec<_>>();
    let aggregate_order_hash = all_order_hashes.compute_aggregate_hash();

    // [5] check that the OP_RETURN inscribed aggregate order hash matches the computed aggregate order hash
    let op_return_output = &transaction.output[op_return_index];
    let op_return_script_pubkey = op_return_output.script_pubkey.as_bytes();

    ensure!(
        op_return_script_pubkey.len() >= 34,
        PaymentValidationFailed {
            reason: "OP_RETURN output script is too short".to_string()
        }
    );

    ensure!(
        op_return_script_pubkey[0] == OP_RETURN_CODE,
        PaymentValidationFailed {
            reason: "Second output is not an OP_RETURN".to_string()
        }
    );

    ensure!(
        op_return_script_pubkey[1] == OP_PUSHBYTES_32,
        PaymentValidationFailed {
            reason: "OP_RETURN script is not pushing 32 bytes".to_string()
        }
    );

    let inscribed_aggregate_order_hash = &op_return_script_pubkey[2..34];

    ensure!(
        inscribed_aggregate_order_hash == aggregate_order_hash,
        PaymentValidationFailed {
            reason: "Inscribed aggregate order hash doesn't match computed aggregate order hash"
                .to_string()
        }
    );

    Ok(all_order_hashes)
}
