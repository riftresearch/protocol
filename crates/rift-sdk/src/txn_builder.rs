use bitcoin::address::NetworkChecked;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Builder;
use bitcoin::sighash::SighashCache;
use bitcoin::{
    consensus::Encodable,
    secp256k1::{self, Secp256k1, SecretKey},
    EcdsaSighashType, PublicKey, Transaction, TxIn, Witness,
};
use bitcoin::{
    transaction, Address, Amount, CompressedPublicKey, Network, OutPoint, PrivateKey, Script,
    ScriptBuf, Sequence, TxOut, Txid,
};
use rift_core::vaults::hash_deposit_vault;
use tokio::time::Instant;

use crate::errors::{Result, RiftSdkError};
use bitcoin_light_client_core::leaves::BlockLeaf;
use bitcoincore_rpc_async::jsonrpc::Transport;
use bitcoincore_rpc_async::{Auth, Client as BitcoinClient, RpcApi};
use futures::stream::TryStreamExt;
use futures::{stream, StreamExt};
use sol_types::Types::DepositVault;
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;

pub struct P2WPKHBitcoinWallet {
    pub secret_key: SecretKey,
    pub public_key: String,
    pub address: Address<NetworkChecked>,
}

impl P2WPKHBitcoinWallet {
    pub fn new(
        secret_key: SecretKey,
        public_key: String,
        address: Address<NetworkChecked>,
    ) -> Self {
        Self {
            secret_key,
            public_key,
            address,
        }
    }

    pub fn from_secret_bytes(secret_key: &[u8; 32], network: Network) -> Self {
        let secret_key = SecretKey::from_slice(secret_key).unwrap();
        let secp = Secp256k1::new();
        let pk = PrivateKey::new(secret_key, network);
        let public_key = PublicKey::from_private_key(&secp, &pk);
        let _unlock_script = public_key.p2wpkh_script_code().unwrap().to_bytes();
        let address = Address::p2wpkh(
            &CompressedPublicKey::from_private_key(&secp, &pk).unwrap(),
            network,
        );
        Self::new(secret_key, public_key.to_string(), address)
    }

    pub fn get_p2wpkh_script(&self) -> ScriptBuf {
        let public_key = PublicKey::from_str(&self.public_key).expect("Invalid public key");
        ScriptBuf::new_p2wpkh(
            &public_key
                .wpubkey_hash()
                .expect("Invalid public key for P2WPKH"),
        )
    }
}

pub fn serialize_no_segwit(tx: &Transaction) -> Vec<u8> {
    let mut buffer = Vec::new();
    tx.version
        .consensus_encode(&mut buffer)
        .expect("Encoding version failed");
    tx.input
        .consensus_encode(&mut buffer)
        .expect("Encoding inputs failed");
    tx.output
        .consensus_encode(&mut buffer)
        .expect("Encoding outputs failed");
    tx.lock_time
        .consensus_encode(&mut buffer)
        .expect("Encoding lock_time failed");
    buffer
}

pub fn build_rift_payment_transaction(
    deposit_vault: &DepositVault,
    in_txid: &Txid,
    transaction: &Transaction,
    in_txvout: u32,
    wallet: &P2WPKHBitcoinWallet,
    fee_sats: u64,
) -> Result<Transaction> {
    let vault_commitment = hash_deposit_vault(deposit_vault);
    let total_lp_sum_btc: u64 = deposit_vault.expectedSats;

    let vin_sats = transaction.output[in_txvout as usize].value.to_sat();

    println!("Total LP Sum BTC: {}", total_lp_sum_btc);
    println!("Vin sats: {}", vin_sats);

    let mut tx_outs = Vec::new();

    // Add liquidity provider outputs
    let amount = deposit_vault.expectedSats;
    let script = Script::from_bytes(&deposit_vault.btcPayoutScriptPubKey.0);
    tx_outs.push(TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: script.into(),
    });

    // Add OP_RETURN output
    let op_return_script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(vault_commitment)
        .into_script();
    tx_outs.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: op_return_script,
    });

    // Add change output
    let change_amount: i64 = vin_sats as i64 - total_lp_sum_btc as i64 - fee_sats as i64;
    if change_amount < 0 {
        return Err(RiftSdkError::InsufficientFunds);
    }
    if change_amount > 0 {
        tx_outs.push(TxOut {
            value: Amount::from_sat(change_amount as u64),
            script_pubkey: wallet.get_p2wpkh_script(),
        });
    }

    // Create input
    let outpoint = OutPoint::new(*in_txid, in_txvout);
    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig: Script::new().into(),
        sequence: Sequence(0xFFFFFFFD),
        witness: Witness::new(),
    };

    // Create unsigned transaction
    let mut tx = Transaction {
        version: transaction::Version(1),
        lock_time: LockTime::from_consensus(0),
        input: vec![tx_in],
        output: tx_outs,
    };

    Ok(sign_transaction(&mut tx, wallet, vin_sats))
}

fn sign_transaction(
    tx: &mut Transaction,
    wallet: &P2WPKHBitcoinWallet,
    input_amount: u64,
) -> Transaction {
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_str(&wallet.public_key).unwrap();

    // We're assuming there's only one input to sign
    let input_index = 0;

    // Create a SighashCache for efficient signature hash computation
    let mut sighash_cache = SighashCache::new(tx.clone());

    // Compute the sighash
    let sighash = sighash_cache
        .p2wpkh_signature_hash(
            input_index,
            &wallet.get_p2wpkh_script(),
            Amount::from_sat(input_amount),
            EcdsaSighashType::All,
        )
        .unwrap();

    // Sign the sighash
    let signature = secp.sign_ecdsa(
        &secp256k1::Message::from_digest_slice(&sighash[..]).unwrap(),
        &wallet.secret_key,
    );

    // Serialize the signature and add the sighash type
    let mut signature_bytes = signature.serialize_der().to_vec();
    signature_bytes.push(EcdsaSighashType::All as u8);

    // Create the witness
    let witness = Witness::from_slice(&[signature_bytes.as_slice(), &public_key.to_bytes()]);

    // Set the witness for the input
    tx.input[input_index].witness = witness;

    tx.clone()
}
