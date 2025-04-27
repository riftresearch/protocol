// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import "./IBitcoinLightClient.sol";

// -- Structs --

struct Order {
    // Where in the order hash array this order is
    uint256 index;
    // When the order was created
    uint64 timestamp;
    // When the order can be refunded (ie. No valid payment was submitted)
    uint64 unlockTimestamp;
    // Amount of ERC20 tokens to be transferred to `designatedReceiver` upon settlement
    uint256 amount;
    // The taker fee prepaid by the order creator, given to the protocol upon settlement
    uint256 takerFee;
    // The expected amount of satoshis that MUST be sent to `bitcoinScriptPubKey` before the order can be settled 
    uint64 expectedSats;
    // The scriptPubKey of the address that will receive the BTC output on the Bitcoin chain
    bytes25 bitcoinScriptPubKey;
    // The address that will receive the ERC20 tokens upon settlement
    address designatedReceiver;
    // The address that created the order
    address owner;
    // A random number used to seed the order hash, to prevent replays of previous payments
    bytes32 salt;
    // The number of blocks that must be built on top of the block containing the payment before the order can be settled
    uint8 confirmationBlocks;
    // Historical Bitcoin block height considered safe from reorganization by the order creator
    uint64 safeBitcoinBlockHeight;
}

enum PaymentState {
    Proved,
    Settled 
}

struct Payment {
    // Where in the payment hash array this payment is
    uint256 index;
    // The hash of the order that this payment is for
    bytes32 orderHash;
    // The Bitcoin block containing the payment
    BlockLeaf paymentBitcoinBlockLeaf;
    // The timestamp at which the payment can be settled
    uint64 challengeExpiryTimestamp;
    // The state of the payment, either `Proved` awaiting settlement or `Settled`
    PaymentState state;
}

enum ProofType {
    PaymentOnly,
    LightClientOnly,
    Combined
}

struct PaymentPublicInput {
    // The Bitcoin transaction ID of the payment
    bytes32 paymentBitcoinTxid;
    // The Bitcoin block hash of the block containing the payment txid
    bytes32 paymentBitcoinBlockHash;
    // The hash of the order that this payment is for
    bytes32 orderHash;
}

struct LightClientPublicInput {
    // The previous MMR root used to generate the new MMR root
    bytes32 priorMmrRoot;
    // The new MMR root generated
    bytes32 newMmrRoot;
    // The hash of all Bitcoin blocks being added to the MMR in this update
    bytes32 compressedLeavesHash;
    // The Bitcoin block leaf at the tip of the updated MMR
    BlockLeaf tipBlockLeaf;
}


struct ProofPublicInput {
    // The type of proof being submitted
    ProofType proofType;
    // The public inputs of the payments being verified in a proof
    PaymentPublicInput[] payments;
    // The light client public input
    LightClientPublicInput lightClient;
}

enum OrderUpdateContext {
    Created,
    Settled,
    Refunded 
}

enum PaymentUpdateContext {
    Created,
    Settled
}

struct BaseCreateOrderParams {
    // The address that will receive the ERC20 tokens upon settlement
    address owner;
    // The scriptPubKey of the address that will receive the BTC output on the Bitcoin chain
    bytes25 bitcoinScriptPubKey;
    // A random number used to seed the order hash, to prevent replays of previous payments
    bytes32 salt;
    // The number of blocks that must be built on top of the block containing the payment before the order can be settled
    uint8 confirmationBlocks;
    // The Bitcoin block leaf at the tip of the MMR considered safe from reorganization by the order creator
    BlockLeaf safeBlockLeaf;
}

struct CreateOrderParams {
    // @inheritdoc BaseCreateOrderParams
    BaseCreateOrderParams base;
    // The address that will receive the ERC20 tokens upon settlement
    address designatedReceiver;
    // The amount of ERC20 tokens to be transferred to `designatedReceiver` upon settlement
    uint256 depositAmount;
    // The expected amount of satoshis that MUST be sent to `bitcoinScriptPubKey` before the order can be settled 
    uint64 expectedSats;
    // The sibling nodes of the Bitcoin block leaf in the MMR considered safe from reorganization by the order creator
    bytes32[] safeBlockSiblings;
    // The peak nodes of the Bitcoin block leaf in the MMR considered safe from reorganization by the order creator
    bytes32[] safeBlockPeaks;
}

struct BlockProofParams {
    // The previous MMR root used to generate the new MMR root
    bytes32 priorMmrRoot;
    // The new MMR root generated
    bytes32 newMmrRoot;
    // The Bitcoin blocks being added to the MMR in this update
    bytes compressedBlockLeaves;
    // The Bitcoin block leaf at the tip of the updated MMR
    BlockLeaf tipBlockLeaf;
}


struct SubmitPaymentProofParams {
    // The Bitcoin transaction ID of the payment
    bytes32 paymentBitcoinTxid;
    // The order that this payment is for
    Order order;
    // The Bitcoin block containing the payment
    BlockLeaf paymentBitcoinBlockLeaf;
    // The sibling nodes of the Bitcoin block containing the payment
    bytes32[] paymentBitcoinBlockSiblings;
    // The peak nodes of the Bitcoin block containing the payment
    bytes32[] paymentBitcoinBlockPeaks;
}

struct SettleOrderParams {
    // The order to settle
    Order order;
    // The payment that settles the order
    Payment payment;
    // The sibling nodes of the Bitcoin block containing the payment
    bytes32[] paymentBitcoinBlockSiblings;
    // The peak nodes of the Bitcoin block containing the payment
    bytes32[] paymentBitcoinBlockPeaks;
    // The height of the Bitcoin block at the tip of the MMR
    uint32 tipBlockHeight;
}


// -----------------------------------------------------------------------
//                                INTERFACE
// -----------------------------------------------------------------------

/**
 * @title RiftExchange
 * @notice A trustless exchange for cross-chain Bitcoin<>Synthetic Bitcoin swaps
 * @dev Uses a Bitcoin light client and zero-knowledge proofs for verification of payment
 */
interface IRiftExchange is IBitcoinLightClient {
    // --- Errors ---

    error InvalidDepositTokenDecimals(uint8 actual, uint8 expected);
    error DepositAmountTooLow();
    error SatOutputTooLow();
    error InvalidScriptPubKey();
    error EmptyDepositVault();
    error DepositStillLocked();
    error NoFeeToPay();
    error InvalidVaultHash(bytes32 actual, bytes32 expected);
    error StillInChallengePeriod();
    error SwapNotProved();
    error NotEnoughConfirmationBlocks();
    error NoSwapsToSubmit();

    // --- Events ---

    event OrdersUpdated(Order[] orders, OrderUpdateContext context);
    event PaymentsUpdated(Payment[] payments, PaymentUpdateContext context);

    // --- Immutables ---
    function syntheticBitcoin() external view returns (address);
    function circuitVerificationKey() external view returns (bytes32);
    function verifier() external view returns (address);

    // --- State Variables ---
    function orderHashes(uint256 index) external view returns (bytes32);
    function paymentHashes(uint256 index) external view returns (bytes32);
    function accumulatedFees() external view returns (uint256);
    function feeRouter() external view returns (address);
    function takerFeeBips() external view returns (uint16);

    // --- External Functions ---
    function withdrawFees() external;
    function adminSetFeeRouter(address _feeRouter) external;
    function adminSetTakerFeeBips(uint16 _takerFeeBips) external;
    function refundOrder(Order calldata order) external;
    function submitPaymentProofs(
        SubmitPaymentProofParams[] calldata paymentParams,
        BlockProofParams calldata blockProofParams,
        bytes calldata proof
    ) external;
    function submitPaymentProofs(
        SubmitPaymentProofParams[] calldata paymentParams,
        bytes calldata proof
    ) external;
    function settleOrders(SettleOrderParams[] calldata settleOrderParams) external;
    function updateLightClient(BlockProofParams calldata blockProofParams, bytes calldata proof) external;

    // --- Read Functions ---
    function getTotalOrders() external view returns (uint256);
    function getTotalPayments() external view returns (uint256);
    function verifyProof(ProofPublicInput memory proofPublicInput, bytes calldata proof) external view;
    // TODO: Do we need this? This exists b/c we need the type in circuits
    function serializeLightClientPublicInput(LightClientPublicInput memory input) external pure returns (bytes memory);
} 