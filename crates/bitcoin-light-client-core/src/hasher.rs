use sha2::{Digest as Sha2Digest, Sha256};
use tiny_keccak::{Hasher as TinyKeccakHasher, Keccak};

pub const DIGEST_BYTE_COUNT: usize = 32;

pub type Digest = [u8; DIGEST_BYTE_COUNT];

pub trait DigestZero {
    const ZERO: Digest;
}

impl DigestZero for Digest {
    const ZERO: Digest = [0u8; DIGEST_BYTE_COUNT];
}

pub trait Hasher {
    fn hash(data: &[u8]) -> Digest;
}

/// Sha256 implementation
pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    fn hash(data: &[u8]) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }
}

/// Keccak256 implementation
pub struct Keccak256Hasher;

impl Hasher for Keccak256Hasher {
    fn hash(data: &[u8]) -> Digest {
        let mut hasher = Keccak::v256();
        hasher.update(data);
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);
        result
    }
}