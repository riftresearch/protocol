import json
from bitcoinlib.blocks import Block


def load_blocks(ignore_before: int = 0):
    blocks = {}
    with open('../test-data/data/headers_0_9999.json', 'r') as file:
        subset_blocks = json.load(file)
        for block in subset_blocks:
            if int(block) < ignore_before:
                continue
            blocks[int(block)] = subset_blocks[block]
    with open('../test-data/data/headers_10000_800000.json', 'r') as file:
        subset_blocks = json.load(file)
        for block in subset_blocks:
            if int(block) < ignore_before:
                continue
            blocks[int(block)] = subset_blocks[block]
    return blocks

def hex_block_to_timestamp(hex_block: str) -> int:
    """
    Extracts timestamp from a block header by direct parsing.
    Bitcoin block headers store the timestamp as a 4-byte integer at bytes 68-72.

    Args:
        hex_block (str): The hexadecimal block string, optionally prefixed with "0x".

    Returns:
        int: The block timestamp.
    """
    # Remove "0x" prefix if present
    if hex_block.startswith("0x"):
        hex_block = hex_block[2:]

    # Convert hexadecimal block to bytes
    block_bytes = bytes.fromhex(hex_block)

    # Timestamp is stored at bytes 68-72 (4 bytes)
    # Convert these 4 bytes to an integer using little-endian format
    timestamp = int.from_bytes(block_bytes[68:72], byteorder='little')

    return timestamp


def analyze_block_times(blocks, windows: range):
    # Convert all timestamps and keep block numbers
    block_numbers = list(blocks.keys())
    timestamps = [hex_block_to_timestamp(block) for block in blocks.values()]
    
    # Calculate time differences between consecutive blocks
    time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    
    # Find longest sequences for different window sizes
    max_times = {}
    max_sequences = {}  # Store the block numbers for longest sequences
    for window in windows:
        if len(time_diffs) >= window-1:
            max_time = 0
            max_start_idx = 0
            for i in range(len(time_diffs) - (window-1) + 1):
                # Sum the time differences for this window
                window_time = sum(time_diffs[i:i+window-1])
                if window_time > max_time:
                    max_time = window_time
                    max_start_idx = i
            max_times[window] = max_time
            max_sequences[window] = (block_numbers[max_start_idx], 
                                   block_numbers[max_start_idx + window - 1])

    return max_times, max_sequences


def print_results(max_times, max_sequences):
    for window, max_time in max_times.items():
        start_block, end_block = max_sequences[window]
        print(f"Longest time to mine {window} sequential blocks: {max_time} seconds ({max_time/60:.2f} minutes)")
        print(f"  Blocks: {start_block} to {end_block}")

# 337340 is the first block in the first difficulty adjustment of 2015 01/03/2015
def get_associated_time_to_mines(windows: range = range(2, 10), ignore_before: int = 337340):
    blocks = load_blocks(ignore_before=ignore_before)
    print(f"Loaded {len(blocks)} blocks")

    print(f"Analyzing blocks between {min(blocks.keys())} and {max(blocks.keys())}")
    max_times, max_sequences = analyze_block_times(blocks, windows=windows)
    return max_times, max_sequences

def main():
    max_times, max_sequences = get_associated_time_to_mines(windows=range(2, 3))
    print_results(max_times, max_sequences)

if __name__ == "__main__":
    main()