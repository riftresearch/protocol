// Effectively a Rust impl of `contracts/src/libraries/CommitmentVerificationLib.sol`
use alloy_sol_types::SolType;
use sol_bindings::Types::DepositVault;
use tiny_keccak::{Hasher, Keccak};

pub fn hash_deposit_vault(vault: &DepositVault) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];

    let abi_encoded = DepositVault::abi_encode(vault);

    hasher.update(&abi_encoded);
    hasher.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    // TODO: LAST, update deposit vault hash tests to include final updated fields
    use std::str::FromStr;

    use super::*;
    use alloy::{
        hex,
        primitives::{Address, FixedBytes, U256},
    };

    /*
    #[test]
    fn test_hash_single_deposit_vault() {
        /*
         */
        let vault = DepositVaultSol {
            vaultIndex: U256::from(16669_u64),
            depositTimestamp: 4077_u64,
            depositAmount: U256::from(14833_u64),
            depositFee: U256::from(599290588_u64),
            expectedSats: 17131086959972120139_u64,
            btcPayoutScriptPubKey: FixedBytes::from_slice(&hex!(
                "00000000000000000000000000000000000000000000"
            )),
            specifiedPayoutAddress: Address::from_str("0x000000000000000000000000000000000000000F")
                .unwrap(),
            ownerAddress: Address::from_str("0x00000000000000000000000000000000000014E7").unwrap(),
            nonce: FixedBytes::from_slice(&hex!(
                "0000000000000000000000000000000000000000000000000000040dac2e8c6e"
            )),
            confirmationBlocks: 129_u8,
            attestedBitcoinBlockHeight: 129_u64,
        };
        let hash = hash_deposit_vault(&vault);
        assert_eq!(
            hash,
            hex!("63e81856360d75073af84951ffb1904c20eeaca5ac18695020adf318b6f770fa")
        );
    }

    #[test]
    fn test_generate_aggregate_vault_commitment_single_vault() {
        let vaults = vec![DepositVaultSol {
            vaultIndex: U256::from(5264_u64),
            depositTimestamp: 4736_u64,
            depositAmount: U256::from(963_u64),
            depositFee: U256::from(18123_u64),
            expectedSats: 3859_u64,
            btcPayoutScriptPubKey: FixedBytes::from_slice(&hex!(
                "00000000000000000000000000000000000000000000"
            )),
            specifiedPayoutAddress: Address::from_str("0x0000000000000000000000000000000000003822")
                .unwrap(),
            ownerAddress: Address::from_str("0x0000000000000000000000000000000000000CEA").unwrap(),
            nonce: FixedBytes::from_slice(&hex!(
                "000000000000000000000000000000000000000000000000000000000000073c"
            )),
            confirmationBlocks: 0_u8,
        }];
        let commitment = generate_aggregate_vault_commitment(&vaults);
        assert_eq!(
            commitment,
            hex!("550b60624e7d86f70361eba1942ae7abf185c8e278f6c7218ca5e46d06e69e02")
        );
    }

    #[test]
    fn test_validate_aggregate_vault_commitment_multiple_vaults() {
        let vaults = vec![
            DepositVaultSol {
                vaultIndex: U256::from(8033_u64),
                depositTimestamp: 87_u64,
                depositAmount: U256::from(2991_u64),
                depositFee: U256::from(6533_u64),
                expectedSats: 469_u64,
                btcPayoutScriptPubKey: FixedBytes::from_slice(&hex!(
                    "00000000000000000000000000000000000000000000"
                )),
                specifiedPayoutAddress: Address::from_str(
                    "0x0000000000000000000000000000000000000EA1",
                )
                .unwrap(),
                ownerAddress: Address::from_str("0x0000000000000000000000000000000000004806")
                    .unwrap(),
                nonce: FixedBytes::from_slice(&hex!(
                    "000000000000000000000000000000000000000000000000000000000000174b"
                )),
                confirmationBlocks: 93_u8,
            },
            DepositVaultSol {
                vaultIndex: U256::from(18717_u64),
                depositTimestamp: 18581_u64,
                depositAmount: U256::from(5892_u64),
                depositFee: U256::from(3230_u64),
                expectedSats: 16583_u64,
                btcPayoutScriptPubKey: FixedBytes::from_slice(&hex!(
                    "00000000000000000000000000000000000000000000"
                )),
                specifiedPayoutAddress: Address::from_str(
                    "0x0000000000000000000000000000000000000022",
                )
                .unwrap(),
                ownerAddress: Address::from_str("0x0000000000000000000000000000000000002d98")
                    .unwrap(),
                nonce: FixedBytes::from_slice(&hex!(
                    "0000000000000000000000000000000000000000000000000000000000004587"
                )),
                confirmationBlocks: 33_u8,
            },
        ];
        let commitment = generate_aggregate_vault_commitment(&vaults);
        assert_eq!(
            commitment,
            hex!("4ad27ddaf2b39959c5e02e10d72639d7aea61adae74b2a6032c163a65ba95408")
        );
    }
    */
}
