// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity =0.8.28;

import "./interfaces/IRiftExchange.sol";
import {ISP1Verifier} from "sp1-contracts/contracts/src/ISP1Verifier.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";

import {EIP712} from "solady/src/utils/EIP712.sol";
import {ERC20} from "solady/src/tokens/ERC20.sol";
import {Ownable} from "solady/src/auth/Ownable.sol";

import {HashLib} from "./libraries/HashLib.sol";
import {PeriodLib} from "./libraries/PeriodLib.sol";
import {BitcoinLightClient} from "./BitcoinLightClient.sol";
import {DataIntegrityLib} from "./libraries/DataIntegrityLib.sol";
import {FeeLib} from "./libraries/FeeLib.sol";
import {MMRProofLib} from "./libraries/MMRProof.sol";
import {BitcoinScriptLib} from "./libraries/BitcoinScriptLib.sol";
import {OrderValidationLib} from "./libraries/OrderValidationLib.sol";

/**
 * @title Rift Exchange
 * @notice A trustless exchange for cross-chain Bitcoin<>Synthetic Bitcoin swaps
 * @dev Uses a Bitcoin light client and zero-knowledge proofs for verification of payment
 */
abstract contract RiftExchange is IRiftExchange, EIP712, Ownable, BitcoinLightClient {
    using SafeTransferLib for address;
    using HashLib for Order;
    using HashLib for Payment;
    using DataIntegrityLib for Order;
    using DataIntegrityLib for Payment;
    using OrderValidationLib for CreateOrderParams;

    address public immutable syntheticBitcoin;
    bytes32 public immutable circuitVerificationKey;
    address public immutable verifier;

    bytes32[] public orderHashes;
    bytes32[] public paymentHashes;
    uint256 public accumulatedFees;
    address public feeRouter;
    uint16 public takerFeeBips;

    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        uint16 _takerFeeBips,
        BlockLeaf memory _tipBlockLeaf
    ) BitcoinLightClient(_mmrRoot, _tipBlockLeaf) {
        _initializeOwner(msg.sender);
        /// @dev Checks within the contract assume that the token has 8 decimals
        uint8 depositTokenDecimals = ERC20(_depositToken).decimals();
        if (depositTokenDecimals != 8) revert InvalidDecimals(depositTokenDecimals, 8);
        syntheticBitcoin = _depositToken;
        circuitVerificationKey = _circuitVerificationKey;
        verifier = _verifier;
        feeRouter = _feeRouter;
        takerFeeBips = _takerFeeBips;
    }

    /// @notice Returns the domain name and version of the contract, used for EIP712 domain separator
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "RiftExchange";
        version = "0.0.1";
    }

    /// @inheritdoc IRiftExchange
    function adminSetFeeRouter(address _feeRouter) external onlyOwner {
        feeRouter = _feeRouter;
    }

    /// @inheritdoc IRiftExchange
    function adminSetTakerFeeBips(uint16 _takerFeeBips) external onlyOwner {
        takerFeeBips = _takerFeeBips;
    }

    /// @inheritdoc IRiftExchange
    function withdrawFees() external {
        uint256 feeBalance = accumulatedFees;
        if (feeBalance == 0) revert NoFeeToWithdraw();
        accumulatedFees = 0;
        syntheticBitcoin.safeTransfer(feeRouter, feeBalance);
    }

    /// @notice Creates a new order for Bitcoin<>Tokenized Bitcoin swap
    /// @dev This function requires that the child contract handles token accounting
    /// @param params The parameters for the order
    function _createOrder(CreateOrderParams memory params) internal {
        // Determine order index
        uint256 orderIndex = orderHashes.length;

        // Create order
        (Order memory order, bytes32 orderHash) = _prepareOrder(params, orderIndex);

        // Add order hash to storage
        orderHashes.push(orderHash);

        // Finalize order creation
        emit OrderCreated(order);
    }

    /// @inheritdoc IRiftExchange
    function refundOrder(Order calldata order) external {
        order.checkIntegrity(orderHashes);
        if (order.state != OrderState.Created) revert OrderNotLive();
        if (block.timestamp < order.unlockTimestamp) revert OrderStillActive();

        Order memory updatedOrder = order;
        // Mark order as refunded
        updatedOrder.state = OrderState.Refunded;

        // Update order hash in storage
        orderHashes[updatedOrder.index] = updatedOrder.hash();

        // Refund order
        syntheticBitcoin.safeTransfer(order.owner, order.amount + order.takerFee);

        emit OrderRefunded(updatedOrder);
    }

    /// @inheritdoc IRiftExchange
    function submitPaymentProofs(
        SubmitPaymentProofParams[] calldata paymentParams,
        BlockProofParams calldata blockProofParams,
        bytes calldata proof
    ) external {
        // optimistically update root, needed b/c we validate current inclusion in the chain for each payment
        _updateRoot(blockProofParams.priorMmrRoot, blockProofParams.newMmrRoot, blockProofParams.tipBlockLeaf);

        uint32 proposedLightClientHeight = blockProofParams.tipBlockLeaf.height;

        (Payment[] memory payments, PaymentPublicInput[] memory paymentPublicInputs) = _validatePayments(
            proposedLightClientHeight,
            paymentParams
        );

        bytes32 compressedLeavesHash = EfficientHashLib.hash(blockProofParams.compressedBlockLeaves);
        verifyProof(
            ProofPublicInput({
                proofType: ProofType.Combined,
                payments: paymentPublicInputs,
                lightClient: LightClientPublicInput({
                    priorMmrRoot: blockProofParams.priorMmrRoot,
                    newMmrRoot: blockProofParams.newMmrRoot,
                    compressedLeavesHash: compressedLeavesHash,
                    tipBlockLeaf: blockProofParams.tipBlockLeaf
                })
            }),
            proof
        );

        emit PaymentsCreated(payments);
    }

    /// @inheritdoc IRiftExchange
    function submitPaymentProofs(SubmitPaymentProofParams[] calldata paymentParams, bytes calldata proof) external {
        uint32 currentLightClientHeight = lightClientHeight();
        (Payment[] memory payments, PaymentPublicInput[] memory paymentPublicInputs) = _validatePayments(
            currentLightClientHeight,
            paymentParams
        );

        verifyProof(
            ProofPublicInput({
                proofType: ProofType.PaymentOnly,
                payments: paymentPublicInputs,
                // null light client public input to align with circuit
                lightClient: LightClientPublicInput({
                    priorMmrRoot: bytes32(0),
                    newMmrRoot: bytes32(0),
                    compressedLeavesHash: bytes32(0),
                    tipBlockLeaf: BlockLeaf({blockHash: bytes32(0), height: 0, cumulativeChainwork: 0})
                })
            }),
            proof
        );
        emit PaymentsCreated(payments);
    }

    /// @inheritdoc IRiftExchange
    function settleOrders(SettleOrderParams[] calldata settleOrderParams) external {
        Payment[] memory updatedPayments = new Payment[](settleOrderParams.length);
        Order[] memory updatedOrders = new Order[](settleOrderParams.length);

        uint256 localFees = 0;
        for (uint256 i = 0; i < settleOrderParams.length; i++) {
            settleOrderParams[i].payment.checkIntegrity(paymentHashes);
            if (settleOrderParams[i].payment.state != PaymentState.Proved) revert PaymentNotProved();
            if (block.timestamp < settleOrderParams[i].payment.challengeExpiryTimestamp)
                revert StillInChallengePeriod();

            bytes32 orderHash = settleOrderParams[i].order.checkIntegrity(orderHashes);
            if (orderHash != settleOrderParams[i].payment.orderHash) {
                revert InvalidOrderHash(settleOrderParams[i].payment.orderHash, orderHash);
            }

            BlockLeaf memory paymentBlockLeaf = settleOrderParams[i].payment.paymentBitcoinBlockLeaf;

            // TODO: consider how to optimize this so this is only called the minimum amount for a given collection of settlements
            _verifyBlockInclusionAndConfirmations(
                paymentBlockLeaf,
                settleOrderParams[i].paymentBitcoinBlockSiblings,
                settleOrderParams[i].paymentBitcoinBlockPeaks,
                settleOrderParams[i].order.confirmationBlocks
            );

            Order memory updatedOrder = settleOrderParams[i].order;
            updatedOrder.state = OrderState.Settled;

            orderHashes[updatedOrder.index] = updatedOrder.hash();

            updatedOrders[i] = updatedOrder;

            Payment memory updatedPayment = settleOrderParams[i].payment;
            updatedPayment.state = PaymentState.Settled;
            paymentHashes[settleOrderParams[i].payment.index] = updatedPayment.hash();

            localFees += settleOrderParams[i].order.takerFee;

            syntheticBitcoin.safeTransfer(
                settleOrderParams[i].order.designatedReceiver,
                settleOrderParams[i].order.amount
            );

            updatedPayments[i] = updatedPayment;
        }

        accumulatedFees += localFees;

        emit OrdersSettled(updatedOrders, updatedPayments);
    }

    /// @inheritdoc IRiftExchange
    function updateLightClient(BlockProofParams calldata blockProofParams, bytes calldata proof) external {
        _updateRoot(blockProofParams.priorMmrRoot, blockProofParams.newMmrRoot, blockProofParams.tipBlockLeaf);

        bytes32 compressedLeavesHash = EfficientHashLib.hash(blockProofParams.compressedBlockLeaves);
        verifyProof(
            ProofPublicInput({
                proofType: ProofType.LightClientOnly,
                payments: new PaymentPublicInput[](0),
                lightClient: LightClientPublicInput({
                    priorMmrRoot: blockProofParams.priorMmrRoot,
                    newMmrRoot: blockProofParams.newMmrRoot,
                    compressedLeavesHash: compressedLeavesHash,
                    tipBlockLeaf: blockProofParams.tipBlockLeaf
                })
            }),
            proof
        );
    }

    /// @inheritdoc IRiftExchange
    function verifyProof(ProofPublicInput memory proofPublicInput, bytes calldata proof) public view {
        ISP1Verifier(verifier).verifyProof(circuitVerificationKey, abi.encode(proofPublicInput), proof);
    }

    // -----------------------------------------------------------------------
    //                            INTERNAL FUNCTIONS
    // -----------------------------------------------------------------------

    /// @notice Internal function to prepare and validate a new order
    function _prepareOrder(
        CreateOrderParams memory params,
        uint256 orderIndex
    ) internal view returns (Order memory, bytes32) {
        uint16 _takerFeeBips = takerFeeBips; // cache

        params.validate(_takerFeeBips);

        verifyBlockInclusion(params.base.safeBlockLeaf, params.safeBlockSiblings, params.safeBlockPeaks);

        uint256 takerFee = FeeLib.calculateFeeFromDeposit(params.depositAmount, _takerFeeBips);

        Order memory order = Order({
            index: orderIndex,
            timestamp: uint64(block.timestamp),
            unlockTimestamp: uint64(
                block.timestamp + PeriodLib.calculateDepositLockupPeriod(params.base.confirmationBlocks)
            ),
            amount: params.depositAmount - takerFee,
            takerFee: takerFee,
            expectedSats: params.expectedSats,
            bitcoinScriptPubKey: params.base.bitcoinScriptPubKey,
            designatedReceiver: params.designatedReceiver,
            owner: params.base.owner,
            salt: EfficientHashLib.hash(_domainSeparator(), params.base.salt, bytes32(orderIndex)),
            confirmationBlocks: params.base.confirmationBlocks,
            safeBitcoinBlockHeight: params.base.safeBlockLeaf.height,
            state: OrderState.Created
        });

        return (order, order.hash());
    }

    /// @notice Internal function to prepare and validate a batch of payment proofs
    function _validatePayments(
        uint32 proposedLightClientHeight,
        SubmitPaymentProofParams[] calldata paymentParams
    ) internal returns (Payment[] memory payments, PaymentPublicInput[] memory paymentPublicInputs) {
        if (paymentParams.length == 0) revert NoPaymentsToSubmit();
        paymentPublicInputs = new PaymentPublicInput[](paymentParams.length);
        payments = new Payment[](paymentParams.length);

        uint256 initialPaymentIndexPointer = paymentHashes.length;
        for (uint256 i = 0; i < paymentParams.length; i++) {
            uint256 paymentIndex = initialPaymentIndexPointer + i;
            SubmitPaymentProofParams calldata params = paymentParams[i];

            bytes32 orderHash = params.order.checkIntegrity(orderHashes);

            paymentPublicInputs[i] = PaymentPublicInput({
                paymentBitcoinTxid: params.paymentBitcoinTxid,
                paymentBitcoinBlockHash: params.paymentBitcoinBlockLeaf.blockHash,
                orderHash: orderHash
            });

            _verifyBlockInclusionAndConfirmations(
                params.paymentBitcoinBlockLeaf,
                params.paymentBitcoinBlockSiblings,
                params.paymentBitcoinBlockPeaks,
                params.order.confirmationBlocks
            );

            payments[i] = Payment({
                index: paymentIndex,
                orderIndex: params.order.index,
                orderHash: orderHash,
                paymentBitcoinBlockLeaf: params.paymentBitcoinBlockLeaf,
                challengeExpiryTimestamp: uint64(
                    block.timestamp +
                        PeriodLib.calculateChallengePeriod(
                            // The challenge period is based on the worst case reorg which would be to the
                            // order creator's originally attested bitcoin block height
                            proposedLightClientHeight - params.order.safeBitcoinBlockHeight
                        )
                ),
                state: PaymentState.Proved
            });

            bytes32 paymentHash = payments[i].hash();
            paymentHashes.push(paymentHash);
        }
    }

    // -----------------------------------------------------------------------
    //                              READ FUNCTIONS
    // -----------------------------------------------------------------------
    /// @inheritdoc IRiftExchange
    function getTotalOrders() external view returns (uint256) {
        return orderHashes.length;
    }

    /// @inheritdoc IRiftExchange
    function getTotalPayments() external view returns (uint256) {
        return paymentHashes.length;
    }
}
