// SPDX-License-Identifier: Unlicensed

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

abstract contract RiftExchange is IRiftExchange, EIP712, Ownable, BitcoinLightClient {
    using SafeTransferLib for address;
    using HashLib for Order;
    using HashLib for Payment;
    using DataIntegrityLib for Order;
    using DataIntegrityLib for Payment;
    using OrderValidationLib for CreateOrderParams;

    // -----------------------------------------------------------------------
    //                                IMMUTABLES
    // -----------------------------------------------------------------------
    address public immutable syntheticBitcoin;
    bytes32 public immutable circuitVerificationKey;
    address public immutable verifier;

    // -----------------------------------------------------------------------
    //                                 STATE
    // -----------------------------------------------------------------------
    bytes32[] public orderHashes;
    bytes32[] public paymentHashes;
    uint256 public accumulatedFees;
    address public feeRouter;
    uint16 public takerFeeBips;

    // -----------------------------------------------------------------------
    //                              CONSTRUCTOR
    // -----------------------------------------------------------------------
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
        /// @dev Deposit token checks within the contract assume that the token has 8 decimals
        uint8 depositTokenDecimals = ERC20(_depositToken).decimals();
        if (depositTokenDecimals != 8) revert InvalidDepositTokenDecimals(depositTokenDecimals, 8);
        syntheticBitcoin = _depositToken;
        circuitVerificationKey = _circuitVerificationKey;
        verifier = _verifier;
        feeRouter = _feeRouter;
        takerFeeBips = _takerFeeBips;
    }

    /// @dev Returns the domain name and version of the contract, used for EIP712 domain separator
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "RiftExchange";
        version = "0.0.1";
    }

    // -----------------------------------------------------------------------
    //                             EXTERNAL FUNCTIONS
    // -----------------------------------------------------------------------

    /// @notice Sends accumulated protocol fees to the fee router contract
    /// @dev Reverts if there are no fees to pay or if the transfer fails
    function withdrawFees() external {
        uint256 feeBalance = accumulatedFees;
        if (feeBalance == 0) revert NoFeeToPay();
        accumulatedFees = 0;
        syntheticBitcoin.safeTransfer(feeRouter, feeBalance);
    }

    function adminSetFeeRouter(address _feeRouter) external onlyOwner {
        feeRouter = _feeRouter;
    }

    function adminSetTakerFeeBips(uint16 _takerFeeBips) external onlyOwner {
        takerFeeBips = _takerFeeBips;
    }

    /// @notice Creates a new order for Bitcoin<>Tokenized Bitcoin swap
    /// @return The hash of the new order
    /// @dev This function requires that the child contract handles token accounting
    function _createOrder(CreateOrderParams memory params) internal returns (bytes32) {
        // Determine order index
        uint256 orderIndex = orderHashes.length;

        // Create order
        (Order memory order, bytes32 orderHash) = _prepareOrder(params, orderIndex);

        // Add order hash to order hashes
        orderHashes.push(orderHash);

        // Finalize order creation
        Order[] memory updatedOrders = new Order[](1);
        updatedOrders[0] = order;
        emit OrdersUpdated(updatedOrders, OrderUpdateContext.Created);

        return orderHash;
    }

    /// @notice Refunds an order after the unlock period if no valid payment was made
    /// @dev Anyone can call, reverts if order doesn't exist, is empty, or still in unlock period
    function refundOrder(Order calldata order) external {
        order.checkIntegrity(orderHashes);
        if (order.amount == 0) revert EmptyDepositVault();
        if (block.timestamp < order.unlockTimestamp) {
            revert DepositStillLocked();
        }

        Order memory updatedOrder = order;
        // Mark order as refunded by zeroing out amount
        updatedOrder.amount = 0;
        updatedOrder.takerFee = 0;

        orderHashes[updatedOrder.index] = updatedOrder.hash();

        syntheticBitcoin.safeTransfer(order.owner, order.amount + order.takerFee);

        Order[] memory updatedOrders = new Order[](1);
        updatedOrders[0] = updatedOrder;
        emit OrdersUpdated(updatedOrders, OrderUpdateContext.Refunded);
    }

    /// @notice Submits a batch of payment proofs with light client update
    function submitPaymentProofs(
        SubmitPaymentProofParams[] calldata paymentParams,
        BlockProofParams calldata blockProofParams,
        bytes calldata proof
    ) external {
        // optimistically update root, needed b/c we validate current inclusion in the chain for each payment
        _updateRoot(
            blockProofParams.priorMmrRoot,
            blockProofParams.newMmrRoot,
            blockProofParams.tipBlockLeaf
        );

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

        emit PaymentsUpdated(payments, PaymentUpdateContext.Created);
    }

    /// @notice Submits a batch of payment proofs without updating the light client
    function submitPaymentProofs(
        SubmitPaymentProofParams[] calldata paymentParams,
        bytes calldata proof
    ) external {
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
        emit PaymentsUpdated(payments, PaymentUpdateContext.Created);
    }

    /// @notice Settles orders by processing verified payments
    function settleOrders(SettleOrderParams[] calldata settleOrderParams) external {
        Payment[] memory updatedPayments = new Payment[](settleOrderParams.length);
        Order[] memory updatedOrders = new Order[](settleOrderParams.length);

        for (uint256 i = 0; i < settleOrderParams.length; i++) {
            settleOrderParams[i].payment.checkIntegrity(paymentHashes);
            if (settleOrderParams[i].payment.state != PaymentState.Proved) revert SwapNotProved();
            if (block.timestamp < settleOrderParams[i].payment.challengeExpiryTimestamp) revert StillInChallengePeriod();

            bytes32 orderHash = settleOrderParams[i].order.checkIntegrity(orderHashes);
            if (orderHash != settleOrderParams[i].payment.orderHash) {
                revert InvalidVaultHash(settleOrderParams[i].payment.orderHash, orderHash);
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
            updatedOrder.amount = 0;
            updatedOrder.takerFee = 0;

            orderHashes[updatedOrder.index] = updatedOrder.hash();

            updatedOrders[i] = updatedOrder;

            Payment memory updatedPayment = settleOrderParams[i].payment;
            updatedPayment.state = PaymentState.Settled;
            paymentHashes[settleOrderParams[i].payment.index] = updatedPayment.hash();

            accumulatedFees += settleOrderParams[i].order.takerFee;

            syntheticBitcoin.safeTransfer(settleOrderParams[i].order.designatedReceiver, settleOrderParams[i].order.amount);

            updatedPayments[i] = updatedPayment;
        }

        emit PaymentsUpdated(updatedPayments, PaymentUpdateContext.Settled);
        emit OrdersUpdated(updatedOrders, OrderUpdateContext.Settled);
    }

    function updateLightClient(BlockProofParams calldata blockProofParams, bytes calldata proof) external {
        _updateRoot(
            blockProofParams.priorMmrRoot,
            blockProofParams.newMmrRoot,
            blockProofParams.tipBlockLeaf
        );

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
            safeBitcoinBlockHeight: params.base.safeBlockLeaf.height
        });

        return (order, order.hash());
    }

    /// @notice Internal function to prepare and validate a batch of payment proofs
    function _validatePayments(
        uint32 proposedLightClientHeight,
        SubmitPaymentProofParams[] calldata paymentParams
    ) internal returns (Payment[] memory payments, PaymentPublicInput[] memory paymentPublicInputs) {
        if (paymentParams.length == 0) revert NoSwapsToSubmit();
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

    // Convenience function to verify a rift proof via eth_call
    function verifyProof(ProofPublicInput memory proofPublicInput, bytes calldata proof) public view {
        ISP1Verifier(verifier).verifyProof(circuitVerificationKey, abi.encode(proofPublicInput), proof);
    }

    // -----------------------------------------------------------------------
    //                              READ FUNCTIONS
    // -----------------------------------------------------------------------

    function getTotalOrders() external view returns (uint256) {
        return orderHashes.length;
    }

    function getTotalPayments() external view returns (uint256) {
        return paymentHashes.length;
    }

    function serializeLightClientPublicInput(
        LightClientPublicInput memory input
    ) external pure returns (bytes memory) {
        return abi.encode(input);
    }
}
