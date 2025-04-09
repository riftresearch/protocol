use bitcoin::consensus::encode::deserialize;
use bitcoin::{Transaction, TxOut};

use sol_bindings::Types::DepositVault;

// Constants
pub const OP_RETURN_CODE: u8 = 0x6a;
pub const OP_PUSHBYTES_32: u8 = 0x20;

// Remove padding from scriptPubKey based on the script type, this padding is added by the contract
pub fn remove_script_pubkey_contract_padding(
    script_pubkey: &[u8; 25],
) -> Result<&[u8], &'static str> {
    match script_pubkey[0] {
        // P2PKH
        0x76 => Ok(&script_pubkey[0..25]),

        // P2SH
        0xa9 => Ok(&script_pubkey[0..23]),

        // P2WPKH:
        0x00 => Ok(&script_pubkey[0..22]),

        // Unknown script type
        _ => Err("Unrecognized scriptPubKey type"),
    }
}

/// Parses a transaction (with segwit data removed), and validates that:
/// 1. The transaction has at least 2 outputs (LP output and OP_RETURN output)
/// 2. The first output matches the expected sats and script pubkey
/// 3. The second output contains an OP_RETURN with the vault commitment
pub fn validate_bitcoin_payment(
    txn_data: &[u8],
    reserved_vault: &DepositVault,
    vault_commitment: &[u8; 32],
) -> Result<(), &'static str> {
    // [0] deserialize txn data
    let transaction: Transaction =
        deserialize(txn_data).map_err(|_| "Failed to deserialize transaction")?;

    // [1] ensure number of outputs is at least 2 (1 LP output + 1 OP_RETURN output)
    let output_counter = transaction.output.len();
    if output_counter < 2 {
        return Err("Transaction must have at least 2 outputs");
    }

    // [2] the first output in the bitcoin transaction is ALWAYS the LP output
    let tx_out: &TxOut = &transaction.output[0];

    // [3] check txn LP payment sats output matches expected sats
    if tx_out.value.to_sat() != reserved_vault.expectedSats {
        return Err("Transaction output value doesn't match expected sats");
    }

    // [4] check txn recipient matches on-chain LP wallet
    let script_pubkey: [u8; 25] = reserved_vault.btcPayoutScriptPubKey.into();
    let script_pubkey_without_padding = remove_script_pubkey_contract_padding(&script_pubkey)?;

    if tx_out.script_pubkey.as_bytes() != script_pubkey_without_padding {
        return Err("Transaction recipient doesn't match LP wallet");
    }

    // [5] the second output in the bitcoin transaction is ALWAYS the OP_RETURN output inscribing the vault commitment
    let op_return_output = &transaction.output[1];
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
    if inscribed_vault_commitment != vault_commitment {
        return Err("Inscribed vault commitment doesn't match on-chain vault commitment");
    }

    Ok(())
}
