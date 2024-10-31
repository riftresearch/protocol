// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.0;

contract TestBlocks {
    bytes32[] public blockHashes;
    uint64[] public blockHeights;
    uint256[] public blockChainworks;

    bytes32 public retargetBlockHash;

    constructor() {
        retargetBlockHash = bytes32(0x00000000000000000000689c53896caf9b969fd8a87ddc0b106d6749e1608101);
        blockHashes = [
            bytes32(0x000000000000000000029224f14319a515d7d9d907ecc89d6fb5f8826e45b3df),
            bytes32(0x00000000000000000002ec7a7ab2fa4e7ecd8cfd02528f6e741b92fd9083000f),
            bytes32(0x000000000000000000007c8df1bbb91fde86d6e49258477eea4148f40877bd35),
            bytes32(0x000000000000000000011c45526d15771fd1bc81c95306d9f5ea4aa289cdbe63),
            bytes32(0x00000000000000000002af268bb0b31a1d9f2307f02d5a942fd810e3a70d4016),
            bytes32(0x00000000000000000002ea113f2897c1c1ac3135564e4ca28fb13c4d972d0802),
            bytes32(0x0000000000000000000141698d233e484894ed5f61ff6d9503f1bc89d043a46f),
            bytes32(0x0000000000000000000092d57f7e1870a0753b6d38c658fdabdb93b844c4353e),
            bytes32(0x00000000000000000002ed368cbcc972b83007eab0fc5a82121409051cc6b99a),
            bytes32(0x000000000000000000016f5e985b007e15a2af91f73ab1d56013712a8e150e41),
            bytes32(0x0000000000000000000025b3fda3bb4bb4f0e60303deca5a018ad02f20ca57fd),
            bytes32(0x000000000000000000021e5439250bec091e0bb5465b6e58eea5c57c1c3fb2f8),
            bytes32(0x0000000000000000000255121d24374bbeee4d8a683d1262e225495cc662e9ae),
            bytes32(0x000000000000000000022fc269917e9aa7b43bdc5474dcc9efe31c08eda0f2a6),
            bytes32(0x00000000000000000001124e11bab04f88f7aab2f85811ef832f5a1de7c06d79),
            bytes32(0x00000000000000000001a2c8a66e188f0e78062f2ecf8be732cfdec377f5b109),
            bytes32(0x000000000000000000017e922704ad7e5b516f5ed5e8298135730976bdffad6d),
            bytes32(0x00000000000000000001c9b3c914cc30bfd9c040ac253a9760b7c85aff5061a2),
            bytes32(0x000000000000000000015c888d7c937d2483ae11cdcc3c76064fa5d4cba642f8),
            bytes32(0x000000000000000000021ff8fc5be1e940e7addc023429a63c37b54fbc1869f5),
            bytes32(0x0000000000000000000154fee13bcefb89191efe549f1c835c11f63a169ce7c0),
            bytes32(0x0000000000000000000058ea22557d7cb00ccf5161a07d99a5f18c9b7cf59c16),
            bytes32(0x0000000000000000000124f5395776b7e7238c7452c5fbd416cb7e676b2b5456),
            bytes32(0x00000000000000000001326f2466f388429013ee5c74cae9120fd5ad9d929a20),
            bytes32(0x00000000000000000003006ac25d488487dabb1056d72ac6a5af44d03a1a2dd8),
            bytes32(0x00000000000000000001c35f9e99a31122fc59a284bc7b5189c003037a3fc329),
            bytes32(0x00000000000000000002aba5bd13dd37f8028b3aa2ffdf4bf3a9568a19769273),
            bytes32(0x00000000000000000001e733a738480f54819daa2edf131798b3dfe476ac2844),
            bytes32(0x00000000000000000001cc2037746cb2bcf7edebf9142746f62a9d6b2df97f7d),
            bytes32(0x00000000000000000002625eba8df7fe74989522362738e17807e399f5e8a099)
        ];
        blockHeights = [
            861295,
            861296,
            861297,
            861298,
            861299,
            861300,
            861301,
            861302,
            861303,
            861304,
            861305,
            861306,
            861307,
            861308,
            861309,
            861310,
            861311,
            861312,
            861313,
            861314,
            861315,
            861316,
            861317,
            861318,
            861319,
            861320,
            861321,
            861322,
            861323,
            861324
        ];
        blockChainworks = [
            44089395307995885530261766224,
            44089793335458630261978069219,
            44090191362921374993694372214,
            44090589390384119725410675209,
            44090987417846864457126978204,
            44091385445309609188843281199,
            44091783472772353920559584194,
            44092181500235098652275887189,
            44092579527697843383992190184,
            44092977555160588115708493179,
            44093375582623332847424796174,
            44093773610086077579141099169,
            44094171637548822310857402164,
            44094569665011567042573705159,
            44094967692474311774290008154,
            44095365719937056506006311149,
            44095763747399801237722614144,
            44096161774862545969438917139,
            44096559802325290701155220134,
            44096957829788035432871523129,
            44097355857250780164587826124,
            44097753884713524896304129119,
            44098151912176269628020432114,
            44098549939639014359736735109,
            44098947967101759091453038104,
            44099345994564503823169341099,
            44099744022027248554885644094,
            44100142049489993286601947089,
            44100540076952738018318250084,
            44100938104415482750034553079
        ];
        blockChainworks = [
            44089395307995885530261766224,
            44089793335458630261978069219,
            44090191362921374993694372214,
            44090589390384119725410675209,
            44090987417846864457126978204,
            44091385445309609188843281199,
            44091783472772353920559584194,
            44092181500235098652275887189,
            44092579527697843383992190184,
            44092977555160588115708493179,
            44093375582623332847424796174,
            44093773610086077579141099169,
            44094171637548822310857402164,
            44094569665011567042573705159,
            44094967692474311774290008154,
            44095365719937056506006311149,
            44095763747399801237722614144,
            44096161774862545969438917139,
            44096559802325290701155220134,
            44096957829788035432871523129,
            44097355857250780164587826124,
            44097753884713524896304129119,
            44098151912176269628020432114,
            44098549939639014359736735109,
            44098947967101759091453038104,
            44099345994564503823169341099,
            44099744022027248554885644094,
            44100142049489993286601947089,
            44100540076952738018318250084,
            44100938104415482750034553079
        ];
    }
}