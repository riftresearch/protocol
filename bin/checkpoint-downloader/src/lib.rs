use bitcoin_light_client_core::leaves::{decompress_block_leaves, BlockLeaf, BlockLeafCompressor};
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use thiserror::Error;

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("Compression IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub fn compress_checkpoint_leaves(
    leaves: &[BlockLeaf],
    output_path: &str,
) -> Result<(), CheckpointError> {
    let serialized_leaves = leaves.compress();
    let zstd_compressed = zstd::encode_all(&*serialized_leaves, 3)?;
    std::fs::write(output_path, zstd_compressed)?;
    Ok(())
}

pub fn decompress_checkpoint_file(input_path: &str) -> Result<Vec<BlockLeaf>, CheckpointError> {
    let input_file = File::open(input_path)?;
    let reader = BufReader::new(input_file);
    let decompressed = zstd::decode_all(reader)?;
    let leaves = decompress_block_leaves(&decompressed);
    Ok(leaves)
}
