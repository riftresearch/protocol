use crypto_bigint::CheckedAdd;
use crypto_bigint::Encoding;
use crypto_bigint::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Header(pub [u8; 80]);

impl Header {
    pub fn as_bytes(&self) -> [u8; 80] {
        self.0
    }
}

impl Serialize for Header {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert array to Vec and serialize
        self.0.to_vec().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Header {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() != 80 {
            return Err(D::Error::custom("Header must be 80 bytes"));
        }
        let mut array = [0u8; 80];
        array.copy_from_slice(&vec);
        Ok(Header(array))
    }
}

// parent_ variables are assumed to be valid in the context of the header chain
// panics on any failures
pub fn validate_header_chain(
    parent_height: u32,
    parent_header: &Header,
    parent_retarget_header: &Header,
    header_chain: &[Header],
) {
    assert!(!header_chain.is_empty(), "Header chain must not be empty");

    let mut retarget_header = *parent_retarget_header;

    for (i, pair) in std::iter::once(parent_header)
        .chain(header_chain.iter())
        .collect::<Vec<_>>()
        .windows(2)
        .enumerate()
    {
        let previous_header = pair[0];
        let previous_height = parent_height + i as u32;
        let current_header = pair[1];

        assert!(
            bitcoin_core_rs::check_header_connection(
                &current_header.as_bytes(),
                &previous_header.as_bytes(),
            ),
            "Header chain link is not connected"
        );

        let next_retarget = bitcoin_core_rs::validate_next_work_required(
            &retarget_header.as_bytes(),
            previous_height,
            &previous_header.as_bytes(),
            &current_header.as_bytes(),
        );

        assert!(
            next_retarget.is_ok(),
            "Failed to validate work requirement: {:?}",
            next_retarget.err().unwrap()
        );

        assert!(
            bitcoin_core_rs::check_proof_of_work(&current_header.as_bytes()),
            "Header fails PoW check"
        );

        retarget_header = Header(next_retarget.unwrap());
    }
}

// Returns the cumulative chainwork for each new header and the final cumulative chainwork for the chain
pub fn calculate_cumulative_work(
    parent_cumulative_work: U256,
    header_chain: &[Header],
) -> (Vec<U256>, U256) {
    assert!(!header_chain.is_empty(), "Header chain must not be empty");
    let works: Vec<U256> = header_chain
        .iter()
        .scan(parent_cumulative_work, |acc, header| {
            let header_proof = bitcoin_core_rs::get_block_proof(&header.as_bytes())
                .expect("Header proof calculation failed");
            *acc = U256::from_le_bytes(header_proof)
                .checked_add(acc)
                .expect("Chainwork addition overflow");
            Some(*acc)
        })
        .collect();

    let final_work = works.last().copied().unwrap_or(parent_cumulative_work);
    let mut all_works = Vec::with_capacity(works.len());
    all_works.extend(works);

    (all_works, final_work)
}

#[cfg(test)]
pub mod tests {
    /*
    Block Header (80 bytes)
    Field Name          Bytes   Byte Range
    Version             4       0-3
    Previous Block      32      4-35
    Merkle Root         32      36-67
    Timestamp           4       68-71
    Bits                4       72-75
    Nonce               4       76-79
    */
    use super::*;

    use test_data_utils::{EXHAUSTIVE_TEST_HEADERS, TEST_HEADERS};

    #[test]
    fn test_validate_header_chain_genesis_step() {
        let genesis_header = &Header(TEST_HEADERS[0].1);

        let header_chain: Vec<Header> = vec![Header(TEST_HEADERS[1].1)];

        validate_header_chain(0, genesis_header, genesis_header, &header_chain);
    }

    #[test]
    fn test_validate_header_chain_first_10_blocks() {
        let genesis_header = &Header(TEST_HEADERS[0].1);

        let header_chain: Vec<Header> = TEST_HEADERS[1..10]
            .iter()
            .map(|(_, header)| Header(*header))
            .collect();

        validate_header_chain(0, genesis_header, genesis_header, &header_chain);
    }

    #[test]
    fn test_validate_header_chain_first_100_blocks() {
        let genesis_header = &Header(TEST_HEADERS[0].1);

        let header_chain: Vec<Header> = TEST_HEADERS[1..100]
            .iter()
            .map(|(_, header)| Header(*header))
            .collect();

        validate_header_chain(0, genesis_header, genesis_header, &header_chain);
    }

    #[test]
    fn test_validate_header_chain_first_1000_blocks() {
        let genesis_header = &Header(TEST_HEADERS[0].1);

        let header_chain: Vec<Header> = TEST_HEADERS[1..1000]
            .iter()
            .map(|(_, header)| Header(*header))
            .collect();
        validate_header_chain(0, genesis_header, genesis_header, &header_chain);
    }

    #[test]
    fn test_validate_header_chain_first_10_000_blocks() {
        let genesis_header = &Header(TEST_HEADERS[0].1);

        let header_chain: Vec<Header> = TEST_HEADERS[1..10000]
            .iter()
            .map(|(_, header)| Header(*header))
            .collect();
        validate_header_chain(0, genesis_header, genesis_header, &header_chain);
    }

    #[test]
    #[ignore = "compute heavy"]
    fn test_validate_header_chain_first_100_000_blocks() {
        let genesis_header = &Header(EXHAUSTIVE_TEST_HEADERS[0].1);
        let header_chain: Vec<Header> = EXHAUSTIVE_TEST_HEADERS[1..100000]
            .iter()
            .map(|(_, header)| Header(*header))
            .collect();
        validate_header_chain(0, genesis_header, genesis_header, &header_chain);
    }

    #[test]
    #[ignore = "compute heavy"]
    fn test_validate_header_chain_first_800_000_blocks() {
        let genesis_header = &Header(EXHAUSTIVE_TEST_HEADERS[0].1);
        let header_chain: Vec<Header> = EXHAUSTIVE_TEST_HEADERS[1..800000]
            .iter()
            .map(|(_, header)| Header(*header))
            .collect();
        validate_header_chain(0, genesis_header, genesis_header, &header_chain);
    }

    #[test]
    #[should_panic(expected = "Header chain must not be empty")]
    fn test_validate_header_chain_empty() {
        let parent_header = &Header(TEST_HEADERS[0].1);

        validate_header_chain(
            0,
            parent_header,
            parent_header, // Using same header as retarget for simplicity
            &[],
        );
    }

    #[test]
    fn test_calculate_cumulative_work() {
        let window_size = 5;

        // Test with a window of headers
        let window = &TEST_HEADERS[..window_size];
        let parent_work = U256::from_u8(0);
        let header_chain: Vec<Header> = window.iter().map(|(_, header)| Header(*header)).collect();

        let (all_works, final_work) = calculate_cumulative_work(parent_work, &header_chain);

        // Basic sanity checks
        assert_eq!(all_works.len(), header_chain.len());
        assert_eq!(*all_works.last().unwrap(), final_work);

        // Verify work is monotonically increasing
        for pair in all_works.windows(2) {
            assert!(pair[0] <= pair[1]);
        }
    }

    #[test]
    #[should_panic(expected = "Header fails PoW check")]
    fn test_validate_header_chain_invalid_pow() {
        let genesis_header = &Header(TEST_HEADERS[0].1);

        // Modify the nonce to invalidate PoW (bytes 76..=79)
        let mut header_bytes = Header(TEST_HEADERS[1].1).as_bytes();
        header_bytes[76..=79].copy_from_slice(&[0; 4]);
        let invalid_header = Header(header_bytes.try_into().unwrap());

        validate_header_chain(0, genesis_header, genesis_header, &[invalid_header]);
    }

    #[test]
    #[should_panic(expected = "Header chain link is not connected")]
    fn test_validate_header_chain_broken_link() {
        let genesis_header = &Header(TEST_HEADERS[0].1);

        // Modify the previous block hash (bytes 4..=35)
        let mut header_bytes = Header(TEST_HEADERS[1].1).as_bytes();
        header_bytes[4..=35].copy_from_slice(&[190; 32]);
        let disconnected_header = Header(header_bytes.try_into().unwrap());

        validate_header_chain(0, genesis_header, genesis_header, &[disconnected_header]);
    }

    #[test]
    #[should_panic(expected = "Failed to validate work requirement")]
    fn test_validate_header_chain_invalid_difficulty() {
        let genesis_header = &Header(TEST_HEADERS[0].1);
        let mut invalid_diff_header = Header(TEST_HEADERS[1].1);

        // Modify bits field (bytes 72..=75)
        let mut header_bytes = invalid_diff_header.as_bytes();
        header_bytes[72..=75].copy_from_slice(&[0xff; 4]);
        invalid_diff_header = Header(header_bytes.try_into().unwrap());

        validate_header_chain(0, genesis_header, genesis_header, &[invalid_diff_header]);
    }

    #[test]
    #[should_panic]
    fn test_calculate_cumulative_work_overflow() {
        // Create a header that would cause work calculation overflow
        let mut overflow_header = Header(TEST_HEADERS[0].1);
        let mut header_bytes = overflow_header.as_bytes();
        header_bytes[28..32].copy_from_slice(&[0x01; 4]);
        overflow_header = Header(header_bytes.try_into().unwrap());

        let max_work = U256::MAX.wrapping_sub(&U256::ONE);
        calculate_cumulative_work(max_work, &[overflow_header]);
    }

    #[test]
    #[should_panic(expected = "Header chain link is not connected")]
    fn test_validate_header_chain_with_gap() {
        let genesis_header = &Header(TEST_HEADERS[0].1);

        // create a chain that skips block 5
        let mut header_chain: Vec<Header> = TEST_HEADERS[1..5]
            .iter()
            .map(|(_, header)| Header(*header))
            .collect();
        header_chain.extend(
            TEST_HEADERS[6..10]
                .iter()
                .map(|(_, header)| Header(*header)),
        );

        validate_header_chain(0, genesis_header, genesis_header, &header_chain);
    }
}
