// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

library BitcoinScriptLib {
    /// @notice Validates that a scriptPubKey follows the P2WPKH format
    /// OP_0(0x00) +
    /// OP_PUSHBYTES_20(0x14) +
    /// <20-byte-pubkey-hash>
    /// P2WPKH == bc1...
    function validateP2WPKHScriptPubKey(bytes22 scriptPubKey) private pure returns (bool) {
        return scriptPubKey[0] == 0x00 && scriptPubKey[1] == 0x14;
    }

    /// @notice Validates that a scriptPubKey follows the P2SH format
    /// OP_HASH160(0xa9) +
    /// OP_PUSHBYTES_20(0x14) +
    /// <20-byte-pubkey-hash> +
    /// OP_EQUAL(0x87))
    /// P2SH == 3...
    function validateP2SHScriptPubKey(bytes23 scriptPubKey) private pure returns (bool) {
        return scriptPubKey[0] == 0xa9 && scriptPubKey[1] == 0x14 && scriptPubKey[22] == 0x87;
    }

    /// @notice Validates that a scriptPubKey follows the P2PKH format
    /// OP_DUP(0x76) +
    /// OP_HASH160(0xa9) +
    /// OP_PUSHBYTES_20(0x14) +
    /// <20-byte-pubkey-hash> +
    /// OP_EQUALVERIFY(0x88) +
    /// OP_CHECKSIG(0xac))
    /// P2PKH == 1...
    function validateP2PKScriptPubKey(bytes25 scriptPubKey) private pure returns (bool) {
        return
            scriptPubKey[0] == 0x76 &&
            scriptPubKey[1] == 0xa9 &&
            scriptPubKey[2] == 0x14 &&
            scriptPubKey[23] == 0x88 &&
            scriptPubKey[24] == 0xac;
    }

    /// @notice Validates that a scriptPubKey follows the P2WPKH, P2SH, or P2PK format
    /// @dev Heuristic used to validate the address type
    function validateScriptPubKey(bytes25 scriptPubKey) internal pure returns (bool) {
        if (scriptPubKey[0] == 0x00) {
            return validateP2WPKHScriptPubKey(bytes22(scriptPubKey));
        } else if (scriptPubKey[0] == 0xa9) {
            return validateP2SHScriptPubKey(bytes23(scriptPubKey));
        } else if (scriptPubKey[0] == 0x76) {
            return validateP2PKScriptPubKey(bytes25(scriptPubKey));
        }
        return false;
    }
}
