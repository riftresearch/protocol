use bitcoin::consensus::encode::deserialize;
use bitcoin::{Transaction, TxOut};

use sol_bindings::Order;

use crate::vaults::SolidityHash;

// Constants
pub const OP_RETURN_CODE: u8 = 0x6a;
pub const OP_PUSHBYTES_32: u8 = 0x20;

/// Parses a transaction (with segwit data removed), and validates that:
/// 1. The transaction has at least 2 outputs (LP output and OP_RETURN output)
/// 2. The nth output matches the expected sats and script pubkey
/// 3. The (n + 1) output contains an OP_RETURN with the vault commitment
pub fn validate_bitcoin_payment(
    txn_data: &[u8],
    order: &Order,
    payment_output_index: usize,
) -> Result<[u8; 32], &'static str> {
    // [0] deserialize txn data
    let transaction: Transaction =
        deserialize(txn_data).map_err(|_| "Failed to deserialize transaction")?;

    // [1] number of outputs is at least large enough to hold the payment and the OP_RETURN output based on the payment index
    let output_counter = transaction.output.len();
    if output_counter < payment_output_index + 2 {
        return Err("Transaction doesn't have enough outputs");
    }

    // [2] get the payment output at the specified index
    let tx_out: &TxOut = &transaction.output[payment_output_index];

    // [3] check txn LP payment sats output matches expected sats
    if tx_out.value.to_sat() != order.expectedSats {
        return Err("Transaction output value doesn't match expected sats");
    }

    // [4] check txn recipient matches order specified wallet
    if tx_out.script_pubkey.as_bytes() != order.bitcoinScriptPubKey.to_vec() {
        return Err("Transaction recipient doesn't match LP wallet");
    }

    // [5] the second output in the bitcoin transaction is ALWAYS the OP_RETURN output inscribing the vault commitment
    let op_return_output = &transaction.output[payment_output_index + 1];
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

    let inscribed_vault_commitment = &op_return_script_pubkey[2..34];

    // [6] check that the OP_RETURN inscribed vault commitment matches on-chain vault commitment
    let order_hash = order.hash();
    if inscribed_vault_commitment != order_hash {
        return Err("Inscribed vault commitment doesn't match on-chain vault commitment");
    }

    Ok(order_hash)
}
