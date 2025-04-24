// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Test} from "forge-std/src/Test.sol";
import {SP1MockVerifier} from "sp1-contracts/contracts/src/SP1MockVerifier.sol";
import {Vm} from "forge-std/src/Vm.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";
import "forge-std/src/console.sol";

import {LightClientVerificationLib} from "../../src/libraries/LightClientVerificationLib.sol";
import {RiftUtils} from "../../src/libraries/RiftUtils.sol";
import {HashLib} from "../../src/libraries/HashLib.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Events} from "../../src/libraries/Events.sol";
import {RiftExchange} from "../../src/RiftExchange.sol";
import {BitcoinLightClient} from "../../src/BitcoinLightClient.sol";
import {MockToken} from "./MockToken.sol";

/// @author Modified from Solady (https://github.com/Vectorized/solady/blob/main/test/utils/TestPlus.sol)
contract PRNG {
    /// @dev This is the keccak256 of a very long string I randomly mashed on my keyboard.
    uint256 private constant _TESTPLUS_RANDOMNESS_SLOT =
        0xd715531fe383f818c5f158c342925dcf01b954d24678ada4d07c36af0f20e1ee;

    /// @dev Multiplier for a mulmod Lehmer psuedorandom number generator.
    /// Prime, and a primitive root of `_LPRNG_MODULO`.
    uint256 private constant _LPRNG_MULTIPLIER = 0x100000000000000000000000000000051;

    /// @dev Modulo for a mulmod Lehmer psuedorandom number generator. (prime)
    uint256 private constant _LPRNG_MODULO = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43;

    /// @dev Returns whether the `value` has been generated for `typeId` and `groupId` before.
    function __markAsGenerated(bytes32 typeId, bytes32 groupId, uint256 value) private returns (bool isSet) {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x00, value)
            mstore(0x20, groupId)
            mstore(0x40, typeId)
            mstore(0x60, _TESTPLUS_RANDOMNESS_SLOT)
            let s := keccak256(0x00, 0x80)
            isSet := sload(s)
            sstore(s, 1)
            mstore(0x40, m) // Restore the free memory pointer.
            mstore(0x60, 0) // Restore the zero pointer.
        }
    }

    /// @dev Returns a pseudorandom random number from [0 .. 2**256 - 1] (inclusive).
    /// For usage in fuzz tests, please ensure that the function has an unnamed uint256 argument.
    /// e.g. `testSomething(uint256) public`.
    /// This function may return a previously returned result.
    function _random() internal returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := _TESTPLUS_RANDOMNESS_SLOT
            let sValue := sload(result)
            mstore(0x20, sValue)
            let r := keccak256(0x20, 0x40)
            // If the storage is uninitialized, initialize it to the keccak256 of the calldata.
            if iszero(sValue) {
                sValue := result
                calldatacopy(mload(0x40), 0x00, calldatasize())
                r := keccak256(mload(0x40), calldatasize())
            }
            sstore(result, add(r, 1))

            // Do some biased sampling for more robust tests.
            // prettier-ignore
            for {} 1 {} {
                let y := mulmod(r, _LPRNG_MULTIPLIER, _LPRNG_MODULO)
                // With a 1/256 chance, randomly set `r` to any of 0,1,2,3.
                if iszero(byte(19, y)) {
                    r := and(byte(11, y), 3)
                    break
                }
                let d := byte(17, y)
                // With a 1/2 chance, set `r` to near a random power of 2.
                if iszero(and(2, d)) {
                    // Set `t` either `not(0)` or `xor(sValue, r)`.
                    let t := or(xor(sValue, r), sub(0, and(1, d)))
                    // Set `r` to `t` shifted left or right.
                    // prettier-ignore
                    for {} 1 {} {
                        if iszero(and(8, d)) {
                            if iszero(and(16, d)) { t := 1 }
                            if iszero(and(32, d)) {
                                r := add(shl(shl(3, and(byte(7, y), 31)), t), sub(3, and(7, r)))
                                break
                            }
                            r := add(shl(byte(7, y), t), sub(511, and(1023, r)))
                            break
                        }
                        if iszero(and(16, d)) { t := shl(255, 1) }
                        if iszero(and(32, d)) {
                            r := add(shr(shl(3, and(byte(7, y), 31)), t), sub(3, and(7, r)))
                            break
                        }
                        r := add(shr(byte(7, y), t), sub(511, and(1023, r)))
                        break
                    }
                    // With a 1/2 chance, negate `r`.
                    r := xor(sub(0, shr(7, d)), r)
                    break
                }
                // Otherwise, just set `r` to `xor(sValue, r)`.
                r := xor(sValue, r)
                break
            }
            result := r
        }
    }

    /// @dev Returns a pseudorandom random number from [0 .. 2**256 - 1] (inclusive).
    /// For usage in fuzz tests, please ensure that the function has an unnamed uint256 argument.
    /// e.g. `testSomething(uint256) public`.
    function _randomUnique(uint256 groupId) internal returns (uint256 result) {
        result = _randomUnique(bytes32(groupId));
    }

    /// @dev Returns a pseudorandom random number from [0 .. 2**256 - 1] (inclusive).
    /// For usage in fuzz tests, please ensure that the function has an unnamed uint256 argument.
    /// e.g. `testSomething(uint256) public`.
    function _randomUnique(bytes32 groupId) internal returns (uint256 result) {
        do {
            result = _random();
        } while (__markAsGenerated("uint256", groupId, result));
    }

    /// @dev Returns a pseudorandom random number from [0 .. 2**256 - 1] (inclusive).
    /// For usage in fuzz tests, please ensure that the function has an unnamed uint256 argument.
    /// e.g. `testSomething(uint256) public`.
    function _randomUnique() internal returns (uint256 result) {
        result = _randomUnique("");
    }

    /// @dev Returns a pseudorandom number, uniformly distributed in [0 .. 2**256 - 1] (inclusive).
    function _randomUniform() internal returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := _TESTPLUS_RANDOMNESS_SLOT
            // prettier-ignore
            for { let sValue := sload(result) } 1 {} {
                // If the storage is uninitialized, initialize it to the keccak256 of the calldata.
                if iszero(sValue) {
                    calldatacopy(mload(0x40), 0x00, calldatasize())
                    sValue := keccak256(mload(0x40), calldatasize())
                    sstore(result, sValue)
                    result := sValue
                    break
                }
                mstore(0x1f, sValue)
                sValue := keccak256(0x20, 0x40)
                sstore(result, sValue)
                result := sValue
                break
            }
        }
    }

    /// @dev Returns a boolean with an approximately 1/n chance of being true.
    /// This function may return a previously returned result.
    function _randomChance(uint256 n) internal returns (bool result) {
        uint256 r = _randomUniform();
        /// @solidity memory-safe-assembly
        assembly {
            result := iszero(mod(r, n))
        }
    }

    /// @dev Returns a pseudorandom address.
    /// The result may have dirty upper 96 bits.
    /// This function will not return an existing contract.
    /// This function may return a previously returned result.
    function _randomAddress() internal returns (address result) {
        uint256 r = _randomUniform();
        /// @solidity memory-safe-assembly
        assembly {
            result := xor(shl(158, r), and(sub(7, shr(252, r)), r))
        }
    }

    /// @dev Returns a pseudorandom address.
    /// The result may have dirty upper 96 bits.
    /// This function will not return an existing contract.
    function _randomUniqueAddress(uint256 groupId) internal returns (address result) {
        result = _randomUniqueAddress(bytes32(groupId));
    }

    /// @dev Returns a pseudorandom address.
    /// The result may have dirty upper 96 bits.
    /// This function will not return an existing contract.
    function _randomUniqueAddress(bytes32 groupId) internal returns (address result) {
        do {
            result = _randomAddress();
        } while (__markAsGenerated("address", groupId, uint160(result)));
    }

    /// @dev Returns a pseudorandom address.
    /// The result may have dirty upper 96 bits.
    /// This function will not return an existing contract.
    function _randomUniqueAddress() internal returns (address result) {
        result = _randomUniqueAddress("");
    }

    /// @dev Returns a pseudorandom non-zero address.
    /// The result may have dirty upper 96 bits.
    /// This function will not return an existing contract.
    /// This function may return a previously returned result.
    function _randomNonZeroAddress() internal returns (address result) {
        uint256 r = _randomUniform();
        /// @solidity memory-safe-assembly
        assembly {
            result := xor(shl(158, r), and(sub(7, shr(252, r)), r))
            if iszero(shl(96, result)) {
                mstore(0x00, result)
                result := keccak256(0x00, 0x30)
            }
        }
    }

    /// @dev Returns a pseudorandom non-zero address.
    /// The result may have dirty upper 96 bits.
    /// This function will not return an existing contract.
    function _randomUniqueNonZeroAddress(uint256 groupId) internal returns (address result) {
        result = _randomUniqueNonZeroAddress(bytes32(groupId));
    }

    /// @dev Returns a pseudorandom non-zero address.
    /// The result may have dirty upper 96 bits.
    /// This function will not return an existing contract.
    function _randomUniqueNonZeroAddress(bytes32 groupId) internal returns (address result) {
        do {
            result = _randomNonZeroAddress();
        } while (__markAsGenerated("address", groupId, uint160(result)));
    }

    /// @dev Returns a pseudorandom non-zero address.
    /// The result may have dirty upper 96 bits.
    /// This function will not return an existing contract.
    function _randomUniqueNonZeroAddress() internal returns (address result) {
        result = _randomUniqueNonZeroAddress("");
    }

    /// @dev Cleans the upper 96 bits of the address.
    /// This is included so that CI passes for older solc versions with --via-ir.
    function _cleaned(address a) internal pure returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := shr(96, shl(96, a))
        }
    }

    /// @dev Returns a pseudorandom hashed address.
    /// The result may have dirty upper 96 bits.
    /// This function will not return an existing contract.
    /// This function will not return a precompile address.
    /// This function will not return a zero address.
    /// This function may return a previously returned result.
    function _randomHashedAddress() internal returns (address result) {
        uint256 r = _randomUniform();
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x1f, and(sub(7, shr(252, r)), r))
            calldatacopy(0x00, 0x00, 0x24)
            result := keccak256(0x00, 0x3f)
        }
    }

    /// @dev Returns a pseudorandom address.
    function _randomUniqueHashedAddress(uint256 groupId) internal returns (address result) {
        result = _randomUniqueHashedAddress(bytes32(groupId));
    }

    /// @dev Returns a pseudorandom address.
    function _randomUniqueHashedAddress(bytes32 groupId) internal returns (address result) {
        do {
            result = _randomHashedAddress();
        } while (__markAsGenerated("address", groupId, uint160(result)));
    }

    /// @dev Returns a pseudorandom address.
    function _randomUniqueHashedAddress() internal returns (address result) {
        result = _randomUniqueHashedAddress("");
    }

    /// @dev Private helper function for returning random bytes.
    function __randomBytes(bool zeroRightPad) private returns (bytes memory result) {
        uint256 r = _randomUniform();
        /// @solidity memory-safe-assembly
        assembly {
            let n := and(r, 0x1ffff)
            let t := shr(24, r)
            for {

            } 1 {

            } {
                // With a 1/256 chance, just return the zero pointer as the result.
                if iszero(and(t, 0xff0)) {
                    result := 0x60
                    break
                }
                result := mload(0x40)
                // With a 15/16 chance, set the length to be
                // exponentially distributed in the range [0,255] (inclusive).
                if shr(252, r) {
                    n := shr(and(t, 0x7), byte(5, r))
                }
                // Store some fixed word at the start of the string.
                // We want this function to sometimes return duplicates.
                mstore(add(result, 0x20), xor(calldataload(0x00), _TESTPLUS_RANDOMNESS_SLOT))
                // With a 1/2 chance, copy the contract code to the start and end.
                if iszero(and(t, 0x1000)) {
                    // Copy to the start.
                    if iszero(and(t, 0x2000)) {
                        codecopy(result, byte(1, r), codesize())
                    }
                    // Copy to the end.
                    codecopy(add(result, n), byte(2, r), 0x40)
                }
                // With a 1/16 chance, randomize the start and end.
                if iszero(and(t, 0xf0000)) {
                    let y := mulmod(r, _LPRNG_MULTIPLIER, _LPRNG_MODULO)
                    mstore(add(result, 0x20), y)
                    mstore(add(result, n), xor(r, y))
                }
                // With a 1/256 chance, make the result entirely zero bytes.
                if iszero(byte(4, r)) {
                    codecopy(result, codesize(), add(n, 0x20))
                }
                // Skip the zero-right-padding if not required.
                if iszero(zeroRightPad) {
                    mstore(0x40, add(n, add(0x40, result))) // Allocate memory.
                    mstore(result, n) // Store the length.
                    break
                }
                mstore(add(add(result, 0x20), n), 0) // Zeroize the word after the result.
                mstore(0x40, add(n, add(0x60, result))) // Allocate memory.
                mstore(result, n) // Store the length.
                break
            }
        }
    }

    /// @dev Returns a random bytes string from 0 to 131071 bytes long.
    /// This random bytes string may NOT be zero-right-padded.
    /// This is intentional for memory robustness testing.
    /// This function may return a previously returned result.
    function _randomBytes() internal returns (bytes memory result) {
        result = __randomBytes(false);
    }

    /// @dev Returns a random bytes string from 0 to 131071 bytes long.
    /// This function may return a previously returned result.
    function _randomBytesZeroRightPadded() internal returns (bytes memory result) {
        result = __randomBytes(true);
    }

    /// @dev Truncate the bytes to `n` bytes.
    /// Returns the result for function chaining.
    function _truncateBytes(bytes memory b, uint256 n) internal pure returns (bytes memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            if gt(mload(b), n) {
                mstore(b, n)
            }
            result := b
        }
    }

    /// @dev Wraps a functions such that allocated memory will be freed at the end of its scope.
    modifier tempMemory() {
        uint256 m = _freeMemoryPointer();
        _;
        _setFreeMemoryPointer(m);
    }

    /// @dev Returns the free memory pointer.
    function _freeMemoryPointer() internal pure returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
        }
    }

    /// @dev Sets the free memory pointer.
    function _setFreeMemoryPointer(uint256 m) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x40, m)
        }
    }

    /// @dev Increments the free memory pointer by a world.
    function _incrementFreeMemoryPointer() internal pure {
        uint256 word = 0x20;
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x40, add(mload(0x40), word))
        }
    }

    /// @dev Adapted from `bound`:
    /// https://github.com/foundry-rs/forge-std/blob/ff4bf7db008d096ea5a657f2c20516182252a3ed/src/StdUtils.sol#L10
    /// Differentially fuzzed tested against the original implementation.
    function _hem(uint256 x, uint256 min, uint256 max) internal pure virtual returns (uint256 result) {
        require(min <= max, "Max is less than min.");
        /// @solidity memory-safe-assembly
        assembly {
            // prettier-ignore
            for {} 1 {} {
                // If `x` is between `min` and `max`, return `x` directly.
                // This is to ensure that dictionary values
                // do not get shifted if the min is nonzero.
                // More info: https://github.com/foundry-rs/forge-std/issues/188
                if iszero(or(lt(x, min), gt(x, max))) {
                    result := x
                    break
                }
                let size := add(sub(max, min), 1)
                if lt(gt(x, 3), gt(size, x)) {
                    result := add(min, x)
                    break
                }
                if lt(lt(x, not(3)), gt(size, not(x))) {
                    result := sub(max, not(x))
                    break
                }
                // Otherwise, wrap x into the range [min, max],
                // i.e. the range is inclusive.
                if iszero(lt(x, max)) {
                    let d := sub(x, max)
                    let r := mod(d, size)
                    if iszero(r) {
                        result := max
                        break
                    }
                    result := sub(add(min, r), 1)
                    break
                }
                let d := sub(min, x)
                let r := mod(d, size)
                if iszero(r) {
                    result := min
                    break
                }
                result := add(sub(max, r), 1)
                break
            }
        }
    }
}

contract RiftTest is Test, PRNG {
    using HashLib for Types.DepositVault;
    using HashLib for Types.ProposedSwap;
    address exchangeOwner = address(0xbeef);
    RiftExchange public exchange;
    MockToken public mockToken;
    SP1MockVerifier public verifier;

    function setUp() public virtual {
        mockToken = new MockToken("Synthetic Bitcoin", "sBTC", 8);
        verifier = new SP1MockVerifier();

        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);

        exchange = new RiftExchange({
            _mmrRoot: initial_mmr_proof.mmrRoot,
            _depositToken: address(mockToken),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier: address(verifier),
            _feeRouter: address(0xfee),
            _takerFeeBips: 5,
            _tipBlockLeaf: initial_mmr_proof.blockLeaf
        });

        mockToken = MockToken(address(exchange.ERC20_BTC()));
    }

    function _callFFI(string memory cmd) internal returns (bytes memory) {
        string[] memory curlInputs = new string[](3);
        curlInputs[0] = "bash";
        curlInputs[1] = "-c";
        curlInputs[2] = cmd;
        return vm.ffi(curlInputs);
    }

    function _callTestUtilsGenerateFakeBlockMMRProof(uint32 height) internal returns (bytes memory) {
        string memory cmd = string.concat(
            "../target/release/sol-utils generate-fake-block-mmr-proof --height ",
            vm.toString(height)
        );
        return _callFFI(cmd);
    }

    function _callTestUtilsGenerateFakeBlockWithConfirmationsMMRProof(
        uint32 height,
        uint32 confirmations
    ) internal returns (bytes memory) {
        string memory cmd = string.concat(
            "../target/release/sol-utils generate-fake-block-with-confirmations-mmr-proof --height ",
            vm.toString(height),
            " --confirmations ",
            vm.toString(confirmations)
        );
        return _callFFI(cmd);
    }

    function _callTestUtilsHashBlockLeaf(bytes memory leaf) internal returns (bytes32) {
        string memory cmd = string.concat(
            "../target/release/sol-utils hash-block-leaf --abi-encoded-leaf ",
            vm.toString(leaf)
        );
        return bytes32(_callFFI(cmd));
    }

    function _generateFakeBlockMMRProofFFI(uint32 height) public returns (Types.MMRProof memory) {
        bytes memory encodedProof = _callTestUtilsGenerateFakeBlockMMRProof(height);
        Types.MMRProof memory proof = abi.decode(encodedProof, (Types.MMRProof));
        return proof;
    }

    function _generateFakeBlockWithConfirmationsMMRProofFFI(
        uint32 height,
        uint32 confirmations
    ) public returns (Types.MMRProof memory, Types.MMRProof memory) {
        bytes memory combinedEncodedProofs = _callTestUtilsGenerateFakeBlockWithConfirmationsMMRProof(
            height,
            confirmations
        );
        Types.ReleaseMMRProof memory releaseProof = abi.decode(combinedEncodedProofs, (Types.ReleaseMMRProof));
        return (releaseProof.proof, releaseProof.tipProof);
    }

    function _hashBlockLeafFFI(Types.BlockLeaf memory leaf) public returns (bytes32) {
        bytes memory encodedLeaf = abi.encode(leaf);
        bytes32 hashedLeaf = _callTestUtilsHashBlockLeaf(encodedLeaf);
        return hashedLeaf;
    }

    function _getMockProof() internal pure returns (bytes memory, bytes memory) {
        bytes memory proof = new bytes(0);
        bytes memory compressedBlockLeaves = abi.encode("compressed leaves");
        return (proof, compressedBlockLeaves);
    }

    function _generateBtcPayoutScriptPubKey() internal returns (bytes22) {
        return bytes22(bytes.concat(bytes2(0x0014), keccak256(abi.encode(_random()))));
    }

    function _extractSingleVaultFromLogs(Vm.Log[] memory logs) internal pure returns (Types.DepositVault memory) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == Events.VaultsUpdated.selector) {
                return abi.decode(logs[i].data, (Types.DepositVault[]))[0];
            }
        }
        revert("Vault not found");
    }

    function _extractSingleSwapFromLogs(Vm.Log[] memory logs) internal pure returns (Types.ProposedSwap memory) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == Events.SwapsUpdated.selector) {
                return abi.decode(logs[i].data, (Types.ProposedSwap[]))[0];
            }
        }
        revert("Swap not found");
    }

    function _depositLiquidityWithAssertions(
        uint256 depositAmount,
        uint64 expectedSats,
        uint8 confirmationBlocks
    ) internal returns (Types.DepositVault memory) {
        // [1] mint and approve deposit token
        mockToken.mint(address(this), depositAmount);
        mockToken.approve(address(exchange), depositAmount);

        // [2] generate a scriptPubKey starting with a valid P2WPKH prefix (0x0014)
        bytes22 btcPayoutScriptPubKey = _generateBtcPayoutScriptPubKey();

        bytes32 depositSalt = bytes32(keccak256(abi.encode(_random())));

        Types.MMRProof memory mmr_proof = _generateFakeBlockMMRProofFFI(0);

        // [3] test deposit
        vm.recordLogs();
        Types.DepositLiquidityParams memory args = Types.DepositLiquidityParams({
            depositOwnerAddress: address(this),
            specifiedPayoutAddress: address(this),
            depositAmount: depositAmount,
            expectedSats: expectedSats,
            btcPayoutScriptPubKey: btcPayoutScriptPubKey,
            depositSalt: depositSalt,
            confirmationBlocks: confirmationBlocks,
            safeBlockLeaf: mmr_proof.blockLeaf,
            safeBlockSiblings: mmr_proof.siblings,
            safeBlockPeaks: mmr_proof.peaks
        });

        exchange.depositLiquidity(args);

        // [4] grab the logs, find the vault
        Types.DepositVault memory createdVault = _extractSingleVaultFromLogs(vm.getRecordedLogs());
        uint256 vaultIndex = exchange.getVaultHashesLength() - 1;
        bytes32 _hash = exchange.getVaultHash(vaultIndex);

        // [5] verify "offchain" calculated hash matches stored vault hash
        bytes32 offchainHash = createdVault.hash();
        assertEq(offchainHash, _hash, "Offchain vault hash should match");

        // [6] verify vault index
        assertEq(createdVault.vaultIndex, vaultIndex, "Vault index should match");

        // [7] verify caller has no balance left
        assertEq(mockToken.balanceOf(address(this)), 0, "Caller should have no balance left");

        // [8] verify owner address
        assertEq(createdVault.ownerAddress, address(this), "Owner address should match");
        return createdVault;
    }
}
