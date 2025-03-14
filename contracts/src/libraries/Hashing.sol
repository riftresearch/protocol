// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Types} from "../libraries/Types.sol";
import {Errors} from "../libraries/Errors.sol";

library EIP712Hashing {
    bytes32 constant AUCTION_TYPE_HASH =
        keccak256("DutchAuctionInfo(uint256 startBlock,uint256 endBlock,uint256 minSats,uint256 maxSats)");
    bytes32 constant BLOCK_LEAF_TYPE_HASH =
        keccak256("BlockLeaf(bytes32 blockHash,uint32 height,uint256 cumulativeChainwork)");
    bytes32 constant DEPOSIT_LIQUIDITY_PARAMS_TYPE_HASH =
        keccak256(
            "ReactorDepositLiquidityParams(address depositOwnerAddress,uint256 depositAmount,bytes25 btcPayoutScriptPubKey,bytes32 depositSalt,uint8 confirmationBlocks,BlockLeaf safeBlockLeaf,bytes32[] safeBlockSiblings,bytes32[] safeBlockPeaks)"
        );
    bytes32 constant INTENT_TYPE_HASH =
        keccak256(
            "IntentInfo(address intentReactor,uint256 nonce,address tokenIn,DutchAuctionInfo auction,ReactorDepositLiquidityParams depositLiquidityParams,Permit2TransferInfo permit2TransferInfo)"
        );
    bytes32 constant PERMIT2_TRANSFER_INFO_HASH =
        keccak256(
            "Permit2TransferInfo(IPermit2.PermitTransferFrom permitTransferFrom,IPermit2.SignatureTransferDetails transferDetails,address owner,bytes signature)"
        );

    /**
     * @notice Validates the EIP‑712 signature for a SignedIntent.
     * @dev Constructs the EIP‑712 digest by:
     *      1. Hashing the DutchAuctionInfo sub-structure using _hashDutchAuctionInfo.
     *      2. Hashing the ReactorDepositLiquidityParams sub-structure using _hashReactorDepositLiquidityParams.
     *      3. Hashing the overall IntentInfo struct using INTENT_TYPE_HASH.
     *      4. Combining with the DOMAIN_SEPARATOR to form the digest.
     *      Finally, it recovers the signer from the digest and compares it with the expected signer
     *      (i.e. the depositOwnerAddress in depositLiquidityParams). If the recovered signer is zero or does not
     *      match, it reverts with InvalidEIP712Signature.
     * @param order The SignedIntent containing the intent data and signature.
     * @return isValid True if the signature is valid.
     */
    function validateEIP712(Types.SignedIntent calldata order) internal view returns (bool isValid) {
        bytes32 intentInfoHash = order.info.hash();
        // Compute the EIP‑712 digest.
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, intentInfoHash));

        // Recover the signer from the digest and the signature.
        address recovered = digest.recover(order.signature);
        if (recovered == address(0) || recovered != order.info.depositLiquidityParams.depositOwnerAddress) {
            revert Errors.InvalidEIP712Signature();
        }
        return true;
    }

    /**
     * @notice Computes the hash of a DutchAuctionInfo struct.
     * @param auction The DutchAuctionInfo struct to hash.
     * @return hash The computed hash.
     */
    function hash(Types.DutchAuctionInfo calldata auction) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(AUCTION_TYPE_HASH, auction.startBlock, auction.endBlock, auction.minSats, auction.maxSats)
            );
    }

    /**
     * @notice Computes the hash of a ReactorDepositLiquidityParams struct.
     * @dev The dynamic arrays (safeBlockSiblings and safeBlockPeaks) are hashed via abi.encodePacked.
     * @param params The ReactorDepositLiquidityParams struct to hash.
     * @return hash The computed hash.
     */
    function hash(Types.ReactorDepositLiquidityParams calldata params) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    DEPOSIT_LIQUIDITY_PARAMS_TYPE_HASH,
                    params.depositOwnerAddress,
                    params.depositAmount,
                    params.btcPayoutScriptPubKey,
                    params.depositSalt,
                    params.confirmationBlocks,
                    hash(params.safeBlockLeaf),
                    keccak256(abi.encodePacked(params.safeBlockSiblings)),
                    keccak256(abi.encodePacked(params.safeBlockPeaks))
                )
            );
    }

    /**
     * @notice Computes the hash of a BlockLeaf struct.
     * @param leaf The BlockLeaf to hash.
     * @return hash The computed hash.
     */
    function hash(Types.BlockLeaf calldata leaf) internal pure returns (bytes32) {
        return keccak256(abi.encode(BLOCK_LEAF_TYPE_HASH, leaf.blockHash, leaf.height, leaf.cumulativeChainwork));
    }

    /**
     * @notice Computes the hash of a Permit2TransferInfo struct.
     * @param info The Permit2TransferInfo struct to hash.
     * @return hash The computed hash.
     */
    function hash(Types.Permit2TransferInfo calldata info) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    PERMIT2_TRANSFER_INFO_HASH,
                    info.permitTransferFrom,
                    info.transferDetails,
                    info.owner,
                    keccak256(info.signature)
                )
            );
    }

    /**
     * @notice Computes the hash of an IntentInfo struct.
     * @param intent The IntentInfo struct to hash.
     * @return hash The computed hash.
     */
    function hash(Types.IntentInfo calldata intent) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    INTENT_TYPE_HASH,
                    intent.intentReactor,
                    intent.nonce,
                    intent.tokenIn,
                    hash(intent.auction),
                    hash(intent.depositLiquidityParams),
                    hash(intent.permit2TransferInfo)
                )
            );
    }
}
