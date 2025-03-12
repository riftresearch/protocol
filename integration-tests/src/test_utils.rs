use alloy::{
    network::EthereumWallet,
    primitives::{keccak256, Address},
    signers::local::LocalSigner,
};
use rift_sdk::txn_builder::P2WPKHBitcoinWallet;

pub fn create_funded_account(
    derivation_salt: u32,
) -> ([u8; 32], EthereumWallet, Address, P2WPKHBitcoinWallet) {
    let maker_secret_bytes: [u8; 32] = keccak256(derivation_salt.to_le_bytes()).into();

    let maker_evm_wallet =
        EthereumWallet::new(LocalSigner::from_bytes(&maker_secret_bytes.into()).unwrap());

    let maker_evm_address = maker_evm_wallet.default_signer().address();

    let maker_btc_wallet =
        P2WPKHBitcoinWallet::from_secret_bytes(&maker_secret_bytes, ::bitcoin::Network::Regtest);

    println!(
        "BTC P2WPKH: {:?}",
        maker_btc_wallet.get_p2wpkh_script().to_hex_string()
    );
    println!("BTC wallet: {:?}", maker_btc_wallet.address);
    println!("EVM wallet: {:?}", maker_evm_address);

    (
        maker_secret_bytes,
        maker_evm_wallet,
        maker_evm_address,
        maker_btc_wallet,
    )
}
