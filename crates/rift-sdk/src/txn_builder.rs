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
    ScriptBuf, Sequence, TxOut, Txid, Weight,
};
use rift_core::order_hasher::SolidityHash;
use rift_core::payments::AggregateOrderHasher;

use crate::btc_txn_broadcaster::{BitcoinSigner, InputUtxo};
use crate::error::{Result, RiftSdkError};
use sol_bindings::Order;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct P2WPKHBitcoinWallet {
    pub secret_key: SecretKey,
    pub public_key: String,
    pub address: Address<NetworkChecked>,
}

impl BitcoinSigner for P2WPKHBitcoinWallet {
    fn sign_transaction(
        &self,
        tx: &Transaction,
        utxo_inputs: &[InputUtxo],
    ) -> eyre::Result<Transaction> {
        let mut tx = tx.clone();
        sign_transaction(&mut tx, self, utxo_inputs);
        Ok(tx)
    }

    fn get_script_pubkey(&self) -> ScriptBuf {
        self.get_p2wpkh_script()
    }

    fn get_address(&self) -> Address<NetworkChecked> {
        self.address.clone()
    }
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

    /// Creates a wallet from a BIP39 mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - The BIP39 mnemonic phrase as a string
    /// * `passphrase` - Optional passphrase for additional security
    /// * `network` - The Bitcoin network to use
    /// * `derivation_path` - Optional custom derivation path, defaults to BIP84 (m/84'/0'/0'/0/0 for mainnet)
    ///
    /// # Returns
    ///
    /// A Result containing the wallet or an error
    pub fn from_mnemonic(
        mnemonic: &str,
        passphrase: Option<&str>,
        network: Network,
        derivation_path: Option<&str>,
    ) -> Result<Self> {
        use bip39::{Language, Mnemonic};
        use bitcoin::bip32::{DerivationPath, Xpriv};

        // Parse and validate the mnemonic
        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|_| RiftSdkError::InvalidMnemonic)?;

        // Determine the appropriate derivation path based on network if not provided
        let path_str = derivation_path.unwrap_or(match network {
            Network::Bitcoin => "m/84'/0'/0'/0/0", // BIP84 for mainnet
            _ => "m/84'/1'/0'/0/0",                // BIP84 for testnet/regtest
        });

        // Parse the derivation path
        let derivation_path =
            DerivationPath::from_str(path_str).map_err(|_| RiftSdkError::InvalidDerivationPath)?;

        // Create seed from mnemonic and optional passphrase
        let seed = mnemonic.to_seed(passphrase.unwrap_or(""));

        // Create master key and derive the child key
        let xpriv =
            Xpriv::new_master(network, &seed[..]).map_err(|_| RiftSdkError::KeyDerivationFailed)?;

        let child_xpriv = xpriv
            .derive_priv(&Secp256k1::new(), &derivation_path)
            .map_err(|_| RiftSdkError::KeyDerivationFailed)?;

        // Convert to private key and extract secret key
        let private_key = PrivateKey::new(child_xpriv.private_key, network);
        let secret_key = private_key.inner;

        // Generate public key and address
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        let address = Address::p2wpkh(
            &CompressedPublicKey::from_private_key(&secp, &private_key).unwrap(),
            network,
        );

        Ok(Self::new(secret_key, public_key.to_string(), address))
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

pub fn serialize_no_segwit(tx: &Transaction) -> eyre::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    tx.version
        .consensus_encode(&mut buffer)
        .map_err(|e| eyre::eyre!("Encoding version failed: {}", e))?;
    tx.input
        .consensus_encode(&mut buffer)
        .map_err(|e| eyre::eyre!("Encoding inputs failed: {}", e))?;
    tx.output
        .consensus_encode(&mut buffer)
        .map_err(|e| eyre::eyre!("Encoding outputs failed: {}", e))?;
    tx.lock_time
        .consensus_encode(&mut buffer)
        .map_err(|e| eyre::eyre!("Encoding lock_time failed: {}", e))?;
    Ok(buffer)
}

pub fn get_outputs_for_orders(orders: &[Order]) -> Vec<TxOut> {
    let order_hashes = orders.iter().map(|order| order.hash()).collect::<Vec<_>>();
    let aggregate_order_hash = order_hashes.compute_aggregate_hash();
    let mut tx_outs = orders
        .iter()
        .map(|order| {
            // Create order payment output
            let amount = order.expectedSats;
            let script_pubkey = &order.bitcoinScriptPubKey.0;

            let script = Script::from_bytes(script_pubkey);
            TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: script.into(),
            }
        })
        .collect::<Vec<_>>();

    // Add OP_RETURN output
    let op_return_script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(aggregate_order_hash)
        .into_script();
    tx_outs.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: op_return_script,
    });
    tx_outs
}

/// Builds a Rift payment transaction with support for multiple UTXO inputs.
///
/// This function creates a Bitcoin transaction that pays to the specified orders
/// and includes an OP_RETURN output with the aggregate order hash. It supports
/// spending from multiple UTXOs, which is useful for:
/// - Combining smaller UTXOs to fund larger payments
/// - Using UTXOs from different transactions
/// - Optimizing fee efficiency by selecting appropriate UTXOs
///
/// # Arguments
///
/// * `orders` - The orders to pay for in this transaction
/// * `utxo_inputs` - A slice of UTXO inputs represented as `(OutPoint, Amount)` tuples
/// * `wallet` - The P2WPKH wallet to sign the transaction with
/// * `fee_sats` - The transaction fee in satoshis
///
/// # Returns
///
/// A signed Bitcoin transaction ready for broadcast, or an error if:
/// - No UTXO inputs are provided
/// - Insufficient funds to cover orders and fees
/// - Transaction signing fails
///
/// # Example
///
/// ```rust
/// use bitcoin::{OutPoint, Amount, Txid};
/// use rift_sdk::txn_builder::{UtxoInput, build_rift_payment_transaction, P2WPKHBitcoinWallet};
/// use bitcoin::Network;
///
/// // Create wallet (example)
/// let secret_bytes = [1u8; 32];
/// let wallet = P2WPKHBitcoinWallet::from_secret_bytes(&secret_bytes, Network::Regtest);
///
/// // Create multiple UTXO inputs using standard Bitcoin types
/// let txid1 = Txid::from_slice(&[1u8; 32]).unwrap();
/// let txid2 = Txid::from_slice(&[2u8; 32]).unwrap();
/// let utxo_inputs: Vec<UtxoInput> = vec![
///     (OutPoint::new(txid1, 0), Amount::from_sat(50_000)),
///     (OutPoint::new(txid2, 1), Amount::from_sat(75_000)),
/// ];
///
/// // Build transaction (orders would be real Order structs)
/// let orders = vec![]; // Empty for example
/// let fee_sats = 1000;
///
/// // This would create a transaction spending from both UTXOs
/// // let tx = build_rift_payment_transaction(&orders, &utxo_inputs, &wallet, fee_sats)?;
/// ```
pub fn build_rift_payment_transaction(
    orders: &[Order],
    utxo_inputs: &[InputUtxo],
    wallet: &P2WPKHBitcoinWallet,
    fee_sats: u64,
) -> Result<Transaction> {
    if utxo_inputs.is_empty() {
        return Err(RiftSdkError::InsufficientFunds);
    }

    let total_input_sats: u64 = utxo_inputs.iter().map(|utxo| utxo.value.to_sat()).sum();
    let cum_orders_expected_sats: u64 = orders.iter().map(|order| order.expectedSats).sum();

    println!(
        "Cumulative Orders Expected Sats: {}",
        cum_orders_expected_sats
    );
    println!("Total input sats: {}", total_input_sats);

    let mut tx_outs = get_outputs_for_orders(orders);

    // Add change output
    let change_amount: i64 =
        total_input_sats as i64 - cum_orders_expected_sats as i64 - fee_sats as i64;
    if change_amount < 0 {
        return Err(RiftSdkError::InsufficientFunds);
    }
    if change_amount > 0 {
        tx_outs.push(TxOut {
            value: Amount::from_sat(change_amount as u64),
            script_pubkey: wallet.get_p2wpkh_script(),
        });
    }

    // Create inputs from UTXOs
    let tx_inputs: Vec<TxIn> = utxo_inputs
        .iter()
        .map(|utxo| {
            let outpoint = utxo.outpoint;
            TxIn {
                previous_output: outpoint,
                script_sig: Script::new().into(),
                sequence: Sequence(0xFFFFFFFD),
                witness: Witness::new(),
            }
        })
        .collect();

    // Create unsigned transaction
    let mut tx = Transaction {
        version: transaction::Version(1),
        lock_time: LockTime::from_consensus(0),
        input: tx_inputs,
        output: tx_outs,
    };

    Ok(sign_transaction(&mut tx, wallet, utxo_inputs))
}

/// Convenience function for building a transaction with a single UTXO input.
/// This maintains backward compatibility with the previous API.
pub fn build_rift_payment_transaction_single_input(
    orders: &[Order],
    in_txid: &Txid,
    transaction: &Transaction,
    in_txvout: u32,
    wallet: &P2WPKHBitcoinWallet,
    fee_sats: u64,
) -> Result<Transaction> {
    let vin_sats = transaction.output[in_txvout as usize].value.to_sat();
    let utxo_input = InputUtxo {
        outpoint: OutPoint::new(*in_txid, in_txvout),
        value: Amount::from_sat(vin_sats),
        weight: Weight::ZERO, // TODO: Calculate weight
    };

    build_rift_payment_transaction(orders, &[utxo_input], wallet, fee_sats)
}

fn sign_transaction(
    tx: &mut Transaction,
    wallet: &P2WPKHBitcoinWallet,
    utxo_inputs: &[InputUtxo],
) -> Transaction {
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_str(&wallet.public_key).unwrap();

    // Create a SighashCache for efficient signature hash computation
    let mut sighash_cache = SighashCache::new(tx.clone());

    // Sign each input
    for (input_index, utxo_input) in utxo_inputs.iter().enumerate() {
        // Compute the sighash for this input
        let sighash = sighash_cache
            .p2wpkh_signature_hash(
                input_index,
                &wallet.get_p2wpkh_script(),
                utxo_input.value,
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

        // Set the witness for this input
        tx.input[input_index].witness = witness;
    }

    tx.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_mnemonic() {
        let wallet = P2WPKHBitcoinWallet::from_mnemonic(
            "panther denial match meadow kingdom crouch convince magic inherit assault response gadget govern benefit forest drift power curious virtual there grid film anxiety stand",
            None,
            Network::Bitcoin,
            None,
        );
        println!("Wallet: {:?}", wallet);
    }

    #[test]
    fn test_utxo_input_creation() {
        use bitcoin::hashes::Hash;

        let txid = Txid::from_slice(&[0u8; 32]).unwrap();
        let outpoint = OutPoint::new(txid, 0);
        let amount = Amount::from_sat(100_000);
        let utxo_input: InputUtxo = InputUtxo {
            outpoint,
            value: amount,
            weight: Weight::ZERO, // TODO: Calculate weight
        };

        assert_eq!(utxo_input.outpoint, outpoint);
        assert_eq!(utxo_input.value, amount);
    }

    #[test]
    fn test_multiple_utxo_inputs() {
        use bitcoin::hashes::Hash;

        let txid1 = Txid::from_slice(&[1u8; 32]).unwrap();
        let txid2 = Txid::from_slice(&[2u8; 32]).unwrap();

        let utxos = [
            (OutPoint::new(txid1, 0), Amount::from_sat(50_000)),
            (OutPoint::new(txid2, 1), Amount::from_sat(75_000)),
        ];

        let total_amount: u64 = utxos.iter().map(|u| u.1.to_sat()).sum();
        assert_eq!(total_amount, 125_000);
    }

    #[test]
    fn test_bitcoin_types_integration() {
        use bitcoin::hashes::Hash;

        // Test that we can create UTXOs using standard Bitcoin types
        let txid = Txid::from_slice(&[42u8; 32]).unwrap();
        let outpoint = OutPoint::new(txid, 5);
        let amount = Amount::from_sat(1_000_000);

        // Create a UTXO input using the type alias
        let utxo_input: InputUtxo = InputUtxo {
            outpoint,
            value: amount,
            weight: Weight::ZERO, // TODO: Calculate weight
        };

        // Verify we can access the components
        assert_eq!(utxo_input.outpoint.txid, txid);
        assert_eq!(utxo_input.outpoint.vout, 5);
        assert_eq!(utxo_input.value.to_sat(), 1_000_000);

        // Test creating multiple UTXOs for a realistic scenario
        let utxos: Vec<InputUtxo> = vec![
            InputUtxo {
                outpoint: OutPoint::new(txid, 0),
                value: Amount::from_sat(100_000),
                weight: Weight::ZERO, // TODO: Calculate weight
            },
            InputUtxo {
                outpoint: OutPoint::new(txid, 1),
                value: Amount::from_sat(250_000),
                weight: Weight::ZERO, // TODO: Calculate weight
            },
            InputUtxo {
                outpoint: OutPoint::new(txid, 2),
                value: Amount::from_sat(500_000),
                weight: Weight::ZERO, // TODO: Calculate weight
            },
        ];

        // Verify total amount calculation
        let total: u64 = utxos.iter().map(|utxo| utxo.value.to_sat()).sum();
        assert_eq!(total, 850_000);

        // Verify we can access individual components
        assert_eq!(utxos[0].outpoint.vout, 0);
        assert_eq!(utxos[1].value, Amount::from_sat(250_000));
        assert_eq!(utxos[2].outpoint.txid, txid);
    }
}
