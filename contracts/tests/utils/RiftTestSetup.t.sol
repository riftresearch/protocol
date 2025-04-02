// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RiftExchange} from "../../src/RiftExchange.sol";
import {RiftReactor} from "../../src/RiftReactor.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";
import {SP1MockVerifier} from "sp1-contracts/contracts/src/SP1MockVerifier.sol";
import {MockToken} from "./MockToken.sol";
import {IPermit2, ISignatureTransfer} from "uniswap-permit2/src/interfaces/IPermit2.sol";
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {RiftTest, RiftExchangeExposed} from "./RiftTest.sol";
import {VaultLib} from "../../src/libraries/VaultLib.sol";

contract RiftReactorExposed is RiftReactor, RiftTest {
    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        Types.BlockLeaf memory _tipBlockLeaf,
        address _permit2_adress
    )
        RiftReactor(
            _mmrRoot,
            _depositToken,
            _circuitVerificationKey,
            _verifier,
            _feeRouter,
            _tipBlockLeaf,
            _permit2_adress
        )
    {}

    function computeBond(uint256 depositAmount) public pure returns (uint96 requiredBond) {
        return _computeBond(depositAmount);
    }

    function computeAuctionSats(Types.DutchAuctionInfo calldata info) public view returns (uint256 expectedSats) {
        return _computeAuctionSats(info);
    }

    function withdrawLiquidity(Types.DepositVault calldata vault) internal {
        _withdrawLiquidity(vault);
    }

    // Access the swapBonds mapping - make this virtual
    function getBondedSwap(bytes32 orderHash) public view virtual returns (Types.BondedSwap memory) {
        return swapBonds[orderHash];
    }

    // Set a value in the swapBonds mapping
    function setSwapBond(bytes32 orderHash, Types.BondedSwap memory bond) public {
        swapBonds[orderHash] = bond;
    }
}

contract RiftTestSetup is RiftTest {
    MockPermit2 public permit2;
    RiftReactorExposed public riftReactor;

    function setUp() public virtual override {
        mockToken = new MockToken("Mock Token", "MTK", 6);
        verifier = new SP1MockVerifier();

        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);

        riftReactor = new RiftReactorExposed({
            _mmrRoot: initial_mmr_proof.mmrRoot,
            _depositToken: address(mockToken),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier: address(verifier),
            _feeRouter: address(0xfee),
            _tipBlockLeaf: initial_mmr_proof.blockLeaf,
            _permit2_adress: address(permit2)
        });

        mockToken = MockToken(address(riftReactor.DEPOSIT_TOKEN()));

        // Mint tokens to the test contract so it can approve depositBond.
        // Adjust the mint amount as needed.
        mockToken.mint(address(this), 1_000_000);
    }
}

/**
 * @title MockPermit2
 * @notice Simplified mock implementation of the Permit2 contract for testing
 * @dev This mock doesn't validate signatures at all for simplicity
 */
contract MockPermit2 {
    function permitTransferFrom(
        ISignatureTransfer.PermitTransferFrom calldata permit,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata /* signature - ignored */
    ) external {
        console.log("MockPermit2.permitTransferFrom called");
        console.log("- Owner:", owner);
        console.log("- Token:", permit.permitted.token);
        console.log("- Amount:", permit.permitted.amount);
        console.log("- To:", transferDetails.to);
        console.log("- Requested amount:", transferDetails.requestedAmount);

        // Skip signature validation completely in the mock

        // Check balance
        uint256 balance = IERC20(permit.permitted.token).balanceOf(owner);
        console.log("- Owner balance:", balance);

        if (balance < transferDetails.requestedAmount) {
            console.log("INSUFFICIENT BALANCE!");
            revert("Insufficient balance");
        }

        uint256 allowance = IERC20(permit.permitted.token).allowance(owner, address(this));
        console.log("- Owner allowance to permit2:", allowance);

        if (allowance < transferDetails.requestedAmount) {
            console.log("INSUFFICIENT ALLOWANCE!");
            revert("Insufficient allowance");
        }

        // Perform the transfer
        console.log("- Transferring tokens...");
        bool success = IERC20(permit.permitted.token).transferFrom(
            owner,
            transferDetails.to,
            transferDetails.requestedAmount
        );

        if (!success) {
            console.log("TRANSFER FAILED!");
            revert("Transfer failed");
        }

        console.log("- Transfer successful");
    }

    // For the tests that need a hash function
    function hash(
        ISignatureTransfer.PermitTransferFrom memory /* permit */,
        uint256 /* requestedAmount */,
        address /* to */
    ) public pure returns (bytes32) {
        // Just return a dummy hash for testing
        return bytes32(uint256(0x123456));
    }
}
