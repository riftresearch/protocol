use bitcoin_light_client_core::leaves::{decompress_block_leaves, BlockLeaf, BlockLeafCompressor};
use std::fs::File;
use std::io::BufReader;

pub fn compress_checkpoint_leaves(
    leaves: &[BlockLeaf],
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let serialized_leaves = leaves.compress();
    let zstd_compressed = zstd::encode_all(&*serialized_leaves, 3)?;
    std::fs::write(output_path, zstd_compressed)?;
    Ok(())
}

pub fn decompress_checkpoint_file(
    input_path: &str,
) -> Result<Vec<BlockLeaf>, Box<dyn std::error::Error>> {
    let input_file = File::open(input_path)?;
    let reader = BufReader::new(input_file);
    let decompressed = zstd::decode_all(reader)?;
    let leaves = decompress_block_leaves(&decompressed);
    Ok(leaves)
}
