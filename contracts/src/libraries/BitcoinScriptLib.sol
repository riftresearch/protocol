// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.28;

/// @title  Bitcoin output-script helper
library BitcoinScriptLib {
    bytes1 private constant OP_0 = bytes1(0x00);
    bytes1 private constant OP_1 = bytes1(0x51);
    bytes1 private constant OP_PUSHBYTES_20 = bytes1(0x14);
    bytes1 private constant OP_PUSHBYTES_32 = bytes1(0x20);
    bytes1 private constant OP_DUP = bytes1(0x76);
    bytes1 private constant OP_EQUAL = bytes1(0x87);
    bytes1 private constant OP_EQUALVERIFY = bytes1(0x88);
    bytes1 private constant OP_HASH160 = bytes1(0xa9);
    bytes1 private constant OP_CHECKSIG = bytes1(0xac);

    /// @notice Validate `scriptPubKey` as one of
    ///         { P2PKH, P2SH, P2WPKH, P2WSH (v0), P2TR (v1) }.
    /// @dev     Accepts *any* length, but fails on unknown length or malformed scriptPubKey.
    function validateScriptPubKey(bytes memory scriptPubKey) internal pure returns (bool) {
        uint256 len = scriptPubKey.length;

        if (len == 22) {
            // P2WPKH
            return validateP2WPKH(scriptPubKey);
        }
        if (len == 23) {
            // P2SH
            return validateP2SH(scriptPubKey);
        }
        if (len == 25) {
            // P2PKH
            return validateP2PKH(scriptPubKey);
        }
        if (len == 34) {
            // Witness v0 (P2WSH) or v1 (P2TR)
            bytes1 version = scriptPubKey[0];
            if (version == OP_0) {
                return validateP2WSH(scriptPubKey);
            }
            if (version == OP_1) {
                return validateP2TR(scriptPubKey);
            }
        }
        return false; // unsupported length / version
    }

    /*
        OP_0
        OP_PUSHBYTES_20
        <20 byte hash>
        Example Address: bc1q9sulnlk30hap692vxhg73gs983qlcudlwk5th6
    */
    function validateP2WPKH(bytes memory s) private pure returns (bool) {
        return s[0] == OP_0 && s[1] == OP_PUSHBYTES_20;
    }

    /*
        OP_HASH160
        OP_PUSHBYTES_20
        <20 byte hash>
        OP_EQUAL
        Example Address: 34y3AcMpDsJ8qmHNkaPM9YPyZ7BQg5pcat
    */
    function validateP2SH(bytes memory s) private pure returns (bool) {
        return (s[0] == OP_HASH160 && s[1] == OP_PUSHBYTES_20 && s[22] == OP_EQUAL);
    }

    /*
        OP_DUP
        OP_HASH160
        OP_PUSHBYTES_20
        <20 byte hash>
        OP_EQUALVERIFY
        OP_CHECKSIG
        Example Address: 14H2F4sNfxykkbawdUikiv33QathBLuHj6
    */
    function validateP2PKH(bytes memory s) private pure returns (bool) {
        return (s[0] == OP_DUP &&
            s[1] == OP_HASH160 &&
            s[2] == OP_PUSHBYTES_20 &&
            s[23] == OP_EQUALVERIFY &&
            s[24] == OP_CHECKSIG);
    }

    /*
        OP_0
        OP_PUSHBYTES_32
        65f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3
        Example Address: bc1q9sulnlk30hap692vxhg73gs983qlcudlzfqjzg3zyg3zyvenxvesf64av0
    */
    function validateP2WSH(bytes memory s) private pure returns (bool) {
        return (s[0] == OP_0 && s[1] == OP_PUSHBYTES_32);
    }

    /*
        OP_1
        OP_PUSHBYTES_32
        0f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667
        Example Address: bc1p9sulnlk30hap692vxhg73gs983qlcudlzfqjzg3zyg3zyvenxvesrd455n
    */
    function validateP2TR(bytes memory s) private pure returns (bool) {
        return (s[0] == OP_1 && s[1] == OP_PUSHBYTES_32);
    }
}
