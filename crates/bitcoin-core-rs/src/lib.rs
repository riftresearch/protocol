pub mod error;

use crate::error::BitcoinError;
use crate::error::Result;

use sha2::{Digest, Sha256};

use crypto_bigint::Encoding;
use crypto_bigint::U256;

use std::convert::TryInto;

pub const POW_LIMIT: U256 =
    U256::from_be_hex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2016;

const TARGET_BLOCK_TIME: u32 = 1209600; // 2 weeks

trait U256Ext {
    // Convert U256 -> 128-bit pair
    fn to_u128_pair(&self) -> (u128, u128);
}

impl U256Ext for U256 {
    fn to_u128_pair(&self) -> (u128, u128) {
        let bytes = self.to_le_bytes();

        // The first 16 bytes are the least-significant bits (the "lower" 128)
        let lower_128 = u128::from_le_bytes(bytes[0..16].try_into().unwrap());

        // The last 16 bytes are the more-significant bits (the "upper" 128)
        let upper_128 = u128::from_le_bytes(bytes[16..32].try_into().unwrap());

        (lower_128, upper_128)
    }
}

trait HeaderExtractor {
    fn time(&self) -> u32;
    fn bits(&self) -> [u8; 4];
    fn previous_block_hash(&self) -> [u8; 32];
}

impl HeaderExtractor for [u8; 80] {
    fn time(&self) -> u32 {
        u32::from_le_bytes(
            self[68..72]
                .try_into()
                .expect("conversion should never fail"),
        )
    }
    fn bits(&self) -> [u8; 4] {
        self[72..76]
            .try_into()
            .expect("conversion should never fail")
    }
    fn previous_block_hash(&self) -> [u8; 32] {
        self[4..36]
            .try_into()
            .expect("conversion should never fail")
    }
}

// modified from https://github.com/rust-bitcoin/rust-bitcoin
fn target_to_bits(target: U256) -> [u8; 4] {
    let mut size = (target.bits() + 7) / 8;
    let (_, upper) = target.to_u128_pair();
    let mut compact = if size <= 3 {
        ((upper as u64) << (8 * (3 - size))) as u32
    } else {
        let bn = target >> (8 * (size - 3));
        let (lower, _) = bn.to_u128_pair();
        lower as u32
    };

    if (compact & 0x0080_0000) != 0 {
        compact >>= 8;
        size += 1;
    }

    (compact | ((size as u32) << 24)).to_le_bytes()
}

// modified from https://github.com/rust-bitcoin/rust-bitcoin
fn bits_to_target(bits: &[u8; 4]) -> U256 {
    let bits = u32::from_le_bytes(*bits);
    let (mant, expt) = {
        let unshifted_expt = bits >> 24;
        if unshifted_expt <= 3 {
            ((bits & 0xFFFFFF) >> (8 * (3 - unshifted_expt as usize)), 0)
        } else {
            (bits & 0xFFFFFF, 8 * ((bits >> 24) - 3))
        }
    };
    if mant > 0x7F_FFFF {
        U256::ZERO
    } else {
        U256::from(mant) << expt as usize
    }
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    // step 1: create new sha256 hash
    let mut hasher = Sha256::new();

    // step 2: update hash blocks with input
    hasher.update(input);

    // return the hash result via .finalize
    let result = hasher.finalize();

    // initialize hash array
    let hash: [u8; 32] = result.into();

    // step 3: return hash
    hash
}

pub fn get_block_hash(header: &[u8; 80]) -> Result<[u8; 32]> {
    // step 1: hash the header via double sha256
    let hash: [u8; 32] = sha256(&sha256(header));

    // step 2: return hash
    Ok(hash)
}

pub fn check_proof_of_work(header: &[u8; 80]) -> bool {
    // step 1: Extract the 'bits' field in the header and convert into byte array
    let bit_bytes: [u8; 4] = header.bits();

    // step 2: pass array to convert the compressed target into fully expanded form
    let target = bits_to_target(&bit_bytes);

    // step 3: Calculate the hash of the header
    let hash = get_block_hash(header);

    // if hash returns expected type continue, else, fail.
    if let Ok(value) = hash {
        // Convert the hash to a little endian U256
        let hash_int = U256::from_le_slice(&value); // reverse order

        // step 4: Compare the hash to the target
        hash_int <= target
    } else {
        false
    }
}

pub fn get_retarget_height(height: u32) -> u32 {
    if DIFFICULTY_ADJUSTMENT_INTERVAL > height {
        return 0;
    }

    (height - 1) / DIFFICULTY_ADJUSTMENT_INTERVAL * DIFFICULTY_ADJUSTMENT_INTERVAL
}

// calculates the new retarget
fn calculate_next_work_required(
    last_retarget_header: &[u8; 80],
    previous_header: &[u8; 80],
) -> [u8; 4] {
    // Limit adjustment step
    let mut timespan = previous_header.time() - last_retarget_header.time();
    if timespan < TARGET_BLOCK_TIME / 4 {
        timespan = TARGET_BLOCK_TIME / 4;
    }
    if timespan > TARGET_BLOCK_TIME * 4 {
        timespan = TARGET_BLOCK_TIME * 4;
    }

    let pow_limit = POW_LIMIT;
    let mut new_target = bits_to_target(&last_retarget_header.bits());

    new_target = new_target.wrapping_mul(&U256::from(timespan));
    new_target = new_target
        .checked_div(&U256::from(TARGET_BLOCK_TIME))
        .expect("Division succeeds");

    if new_target > pow_limit {
        new_target = pow_limit;
    }

    target_to_bits(new_target)
}

pub fn validate_next_work_required(
    last_retarget_header: &[u8; 80],
    previous_height: u32,
    previous_header: &[u8; 80],
    current_header: &[u8; 80],
) -> Result<[u8; 80]> {
    if (previous_height + 1) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
        let current_header_difficulty = current_header.bits();

        let calculated_difficulty =
            calculate_next_work_required(last_retarget_header, previous_header);

        if current_header_difficulty == calculated_difficulty {
            Ok(*current_header)
        } else {
            Err(BitcoinError::WorkRequirementError)
        }
    } else {
        Ok(*last_retarget_header)
    }
}

pub fn get_block_proof(header: &[u8; 80]) -> Result<[u8; 32]> {
    let target: U256 = bits_to_target(&header.bits());

    if target == U256::ZERO {
        Ok([0u8; 32])
    } else {
        let result: [u8; 32] = (U256::MAX)
            .checked_div(&target.saturating_add(&U256::ONE))
            .expect("Division succeeds")
            .to_le_bytes();

        Ok(result)
    }
}

pub fn check_header_connection(header: &[u8; 80], previous_header: &[u8; 80]) -> bool {
    // step 1: get previous block hash in current header
    let curr_header: [u8; 32] = header.previous_block_hash();

    // step 2: get the hash of the previous header
    let last_header_hash: [u8; 32] = get_block_hash(previous_header).unwrap();

    // step 3: compare and see if the hashes connect - if true, connection valid.
    curr_header == last_header_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
    use alloy_primitives::U256;
    use std::collections::HashMap;

    // Define a HashMap of height to hex values
    fn get_headers() -> HashMap<u32, &'static [u8; 80]> {
        let mut headers = HashMap::new();
        headers.insert(38304, &hex!("01000000858a5c6d458833aa83f7b7e56d71c604cb71165ebb8104b82f64de8d00000000e408c11029b5fdbb92ea0eeb8dfa138ffa3acce0f69d7deebeb1400c85042e01723f6b4bc38c001d09bd8bd5"));
        headers.insert(40318, &hex!("0100000007aa5faf1c4273054f1d415318ffc140afacd41708e47442c496e63a00000000a7176bc7da91e5eedfb39c0ad51e58f06f80e45b2edcd3ca900eee746fe1b2f19b86784bc38c001d8ede8c07"));
        headers.insert(40319, &hex!("01000000a4eaafee7ae520b206e56ae73af34cdeedf022fd000081ef74a4830600000000396f6849a2da8ddd7c3452647f30c2fe9feb3e5c089bd1eb36808374ca36d7b4f986784bc38c001d6047eb01"));
        headers.insert(40320, &hex!("010000001a231097b6ab6279c80f24674a2c8ee5b9a848e1d45715ad89b6358100000000a822bafe6ed8600e3ffce6d61d10df1927eafe9bbf677cb44c4d209f143c6ba8db8c784b5746651cce222118"));
        headers.insert(40321, &hex!("0100000045720d24eae33ade0d10397a2e02989edef834701b965a9b161e864500000000993239a44a83d5c427fd3d7902789ea1a4d66a37d5848c7477a7cf47c2b071cd7690784b5746651c3af7ca03"));
        headers
    }

    #[test]
    fn test_sha256() {
        let test_bytes = hex!("deadbeef");
        let hash = sha256(&test_bytes);
        assert_eq!(
            hash,
            hex!("5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953")
        );
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(&[]);
        assert_eq!(
            hash,
            hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn test_check_pow_real_block() {
        // Test case 1: Valid bitcoin block header that meets PoW requirement
        let serialized_header =
            hex!("00606a2a6da096d2b8dbbbed775ac73ebffb4f8005625ff082d902000000000000000000636f25b00a6dba593285caae62bc20cb5c022050efdae664ff52255c1c2e1b754de10867cd0e031739d4a0ef");
        assert!(check_proof_of_work(&serialized_header));
    }

    #[test]
    fn test_check_pow_null_header() {
        let serialized_header =
            hex!("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        assert!(!check_proof_of_work(&serialized_header));
    }

    #[test]
    fn test_check_pow_fake_block() {
        let serialized_header =
            hex!("010000006024f927c294aafe77f7eff56d0d35e9309dc6a5595b54ffa79200000000000002d8003f9c8c10750d7cb64d3e9cd36cdfc3f0b20db3afd1f25b3657002515a5fa71b04dacb5001ba2e71604");
        assert!(!check_proof_of_work(&serialized_header));
    }

    #[test]
    fn test_header_hash() {
        let mut expected_hash =
            hex!("0000000015bb50096055846954f7120e30d6aa2bd5ab8d4a4055ceacc853328a");
        expected_hash.reverse();
        let header = hex!("01000000858a5c6d458833aa83f7b7e56d71c604cb71165ebb8104b82f64de8d00000000e408c11029b5fdbb92ea0eeb8dfa138ffa3acce0f69d7deebeb1400c85042e01723f6b4bc38c001d09bd8bd5");
        let hash = get_block_hash(&header).unwrap();
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_get_retarget_height() {
        assert_eq!(get_retarget_height(0), 0);
        assert_eq!(get_retarget_height(2015), 0);
        assert_eq!(get_retarget_height(2016), 0);
        assert_eq!(get_retarget_height(2017), 2016);

        assert_eq!(get_retarget_height(4031), 2016);
        assert_eq!(get_retarget_height(4032), 2016);
        assert_eq!(get_retarget_height(4033), 4032);

        assert_eq!(get_retarget_height(40319), 38304);
        assert_eq!(get_retarget_height(40320), 38304);
        assert_eq!(get_retarget_height(40321), 40320);
    }

    #[test]
    fn test_get_next_work_required_during_retarget() {
        let headers = get_headers();
        let retarget_height = 38304;
        let previous_height = 40319;
        let next_height = 40320;
        let last_retarget_header = *headers.get(&retarget_height).unwrap();
        let previous_header = *headers.get(&previous_height).unwrap();
        let new_header = *headers.get(&next_height).unwrap();

        let result = validate_next_work_required(
            last_retarget_header,
            previous_height,
            previous_header,
            new_header,
        )
        .unwrap();

        // The 40320 was a retarget block, so the next retarget header should be the same as the new header
        assert_eq!(result, *new_header);
    }

    #[test]
    fn test_get_next_work_required_right_before_retarget() {
        let headers = get_headers();
        let retarget_height = 38304;
        let previous_height = 40318;
        let next_height = 40319;
        let last_retarget_header = *headers.get(&retarget_height).unwrap();
        let previous_header = *headers.get(&previous_height).unwrap();
        let new_header = *headers.get(&next_height).unwrap();

        let result = validate_next_work_required(
            last_retarget_header,
            previous_height,
            previous_header,
            new_header,
        )
        .unwrap();

        // The 40319 was a normal block so it should be the same as the original retarget header
        assert_eq!(result, *last_retarget_header);
    }

    #[test]
    fn test_get_next_work_required_right_retarget_is_previous() {
        let headers = get_headers();
        let retarget_height = 40320;
        let previous_height = 40320;
        let next_height = 40321;
        let last_retarget_header = *headers.get(&retarget_height).unwrap();
        let previous_header = *headers.get(&previous_height).unwrap();
        let new_header = *headers.get(&next_height).unwrap();

        let result = validate_next_work_required(
            last_retarget_header,
            previous_height,
            previous_header,
            new_header,
        )
        .unwrap();

        assert_eq!(result, *last_retarget_header);
    }

    // this test is useful to make sure that we're retargeting to new headers
    // even if a difficulty adjustment doesn't occur
    #[test]
    fn test_get_next_work_required_before_first_difficulty_adjustment() {
        let previous_height = 30239;
        let previous_header = hex!("01000000e8f9ca4b3e84dabb0a95630692810d7485e203bae781b93b0c43f70900000000889c30533589222d82dc2314bda2154e8ad6b89d626231fd5e200555805f6d3faf4b2b4bffff001d072a9d6f");
        let next_header = hex!("01000000e6bf7fd7f7790a63786faa878d0dc7fd8f2ff365732e45862c66075100000000700d342f65c7b6834dffb615358a1897016f0448913372190cbe3d27a4b53355b1512b4bffff001dbfb02519");
        let previous_retarget_height = 28224;
        assert_eq!(
            get_retarget_height(previous_height),
            previous_retarget_height
        );
        let last_retarget_header = hex!("010000000bc8739494b0c7c5a575a09b33af1e44fd6eaf71064e8c8900a7f1f900000000374f258b62986d40f1596532151567e3084ab391177e7676ab046e6e2b7cd594cb49104bffff001ddc4fd604");

        let result = validate_next_work_required(
            &last_retarget_header,
            previous_height,
            &previous_header,
            &next_header,
        )
        .unwrap();
        assert_ne!(
            result, last_retarget_header,
            "Even though the difficulty adjustment didn't occur, retarget to the new header"
        );
    }

    #[test]
    fn test_get_block_proof_genesis_block() {
        let mut expected_proof =
            hex!("0000000000000000000000000000000000000000000000000000000100010001");
        expected_proof.reverse();
        let genesis_header = hex!("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c");
        let proof = get_block_proof(&genesis_header).unwrap();
        assert_eq!(proof, expected_proof);
    }

    #[test]
    fn test_get_block_proof_standard_block() {
        let mut expected_proof =
            hex!("0000000000000000000000000000000000000000000000000000aa83470b0222");
        expected_proof.reverse();

        let mut previous_header_proof =
            hex!("0000000000000000000000000000000000000000000000000000aa80bfeea100");
        previous_header_proof.reverse();

        // block 40320
        let header = hex!("010000001a231097b6ab6279c80f24674a2c8ee5b9a848e1d45715ad89b6358100000000a822bafe6ed8600e3ffce6d61d10df1927eafe9bbf677cb44c4d209f143c6ba8db8c784b5746651cce222118");
        let proof = get_block_proof(&header).unwrap();

        let calculated_chainwork: [u8; 32] =
            (U256::from_le_bytes(previous_header_proof) + U256::from_le_bytes(proof)).to_le_bytes();

        assert_eq!(calculated_chainwork, expected_proof);
    }

    #[test]
    fn test_header_connection() {
        let headers = get_headers();

        // Test connecting headers 40319 -> 40320
        let header_40320 = headers.get(&40320).unwrap();
        let header_40319 = headers.get(&40319).unwrap();
        assert!(check_header_connection(header_40320, header_40319));

        // Test connecting headers 40320 -> 40321
        let header_40321 = headers.get(&40321).unwrap();
        assert!(check_header_connection(header_40321, header_40320));

        // Test invalid connection
        assert!(!check_header_connection(header_40321, header_40319));
    }
}
