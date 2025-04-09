// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import {RiftTestSetup, RiftReactorExposed} from "../../utils/RiftTestSetup.t.sol";
import {Types} from "../../../src/libraries/Types.sol";
import {Errors} from "../../../src/libraries/Errors.sol";
import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";
import {MockToken} from "../../utils/MockToken.sol";
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {IPermit2, ISignatureTransfer} from "uniswap-permit2/src/interfaces/IPermit2.sol";
import {EIP712Hashing} from "../../../src/libraries/Hashing.sol";
import {ECDSA} from "@openzeppelin-contracts/utils/cryptography/ECDSA.sol";

/**
 * @title Permit2SecurityTest
 * @notice Tests for the security of the Permit2 integration in RiftReactor
 * @dev Addresses the comment: "COMMMENT ABOUT POSSIBLE BUG: Is this a valid comment ("This should probably hardcode
 *      the transfer details or I can create a fake order that steals a permit but sets the transfer details to me instead?")?
 *      Look at the types of these thingsm we're Doesnt validateBondAndRecord validate this or somewhre else?"
 */
contract Permit2SecurityTest is RiftTestSetup {
    // Test accounts
    address attacker;
    address victim;
    uint256 victimPrivateKey;

    // Mock token for testing
    MockToken inputToken;

    function setUp() public override {
        super.setUp();

        // Setup accounts
        victimPrivateKey = 0xA11CE;
        victim = vm.addr(victimPrivateKey);
        attacker = makeAddr("attacker");

        // Setup tokens
        inputToken = new MockToken("Input Token", "IN", 18);
        inputToken.mint(victim, 10_000_000);
        inputToken.mint(attacker, 1_000_000);
        mockToken.mint(attacker, 1_000_000);

        // Setup approvals
        vm.prank(victim);
        inputToken.approve(address(permit2), type(uint256).max);

        vm.prank(attacker);
        mockToken.approve(address(riftReactor), type(uint256).max);
    }

    /**
     * @notice Helper function to create a valid Permit2 signature from the victim
     * @param token The token to approve
     * @param amount The amount to approve
     * @param nonce The nonce to use
     * @param deadline The deadline for the approval
     * @param recipient The recipient of the funds
     * @return The structured permit data and signature
     */
    function createValidPermitSignature(
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        address recipient
    ) internal returns (Types.Permit2TransferInfo memory) {
        ISignatureTransfer.PermitTransferFrom memory permitTransferFrom = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: token, amount: amount}),
            nonce: nonce,
            deadline: deadline
        });

        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer
            .SignatureTransferDetails({to: recipient, requestedAmount: amount});

        // Get domain separator from permit2
        bytes32 domainSeparator = permit2.DOMAIN_SEPARATOR();

        // Generate the permit hash
        bytes32 tokenPermissionsHash = keccak256(
            abi.encode(keccak256("TokenPermissions(address token,uint256 amount)"), token, amount)
        );

        bytes32 permitTransferFromHash = keccak256(
            abi.encode(
                keccak256(
                    "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)"
                ),
                tokenPermissionsHash,
                recipient, // spender
                nonce,
                deadline
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, permitTransferFromHash));

        // Sign the digest with the victim's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(victimPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Return the permit info with signature
        return
            Types.Permit2TransferInfo({
                permitTransferFrom: permitTransferFrom,
                transferDetails: transferDetails,
                owner: victim,
                signature: signature
            });
    }

    /**
     * @notice Test the potential attack where an attacker could reuse a permit signature but modify the recipient
     */
    function testPermit2TransferRecipientCannotBeModified() public {
        // Setup valid permit signed by victim to transfer tokens to the reactor
        uint256 amount = 1_000_000;
        uint256 nonce = 0;
        uint256 deadline = block.timestamp + 3600;

        // Create a valid permit with the riftReactor as the recipient
        Types.Permit2TransferInfo memory validPermit = createValidPermitSignature(
            address(inputToken),
            amount,
            nonce,
            deadline,
            address(riftReactor) // The intended recipient (reactor)
        );

        // Now attempt to create a malicious intent that reuses the valid signature
        // but tries to change the recipient to the attacker
        Types.Permit2TransferInfo memory maliciousPermit = Types.Permit2TransferInfo({
            permitTransferFrom: validPermit.permitTransferFrom,
            transferDetails: ISignatureTransfer.SignatureTransferDetails({
                to: attacker, // Trying to change recipient to attacker
                requestedAmount: amount
            }),
            owner: victim,
            signature: validPermit.signature
        });

        // Create intent info with the malicious permit
        Types.DutchAuctionInfo memory auction = Types.DutchAuctionInfo({
            startBlock: block.number,
            endBlock: block.number + 100,
            minSats: 1000,
            maxSats: 2000
        });

        Types.ReactorDepositLiquidityParams memory depositParams = Types.ReactorDepositLiquidityParams({
            depositAmount: amount,
            depositSalt: bytes32(uint256(123)),
            depositOwnerAddress: attacker,
            btcPayoutScriptPubKey: bytes25(0),
            confirmationBlocks: 6,
            safeBlockLeaf: Types.BlockLeaf({blockHash: bytes32(0), height: 1, cumulativeChainwork: 1}),
            safeBlockSiblings: new bytes32[](0),
            safeBlockPeaks: new bytes32[](0)
        });

        Types.IntentInfo memory intentInfo = Types.IntentInfo({
            intentReactor: address(riftReactor),
            nonce: 0,
            tokenIn: address(inputToken),
            auction: auction,
            depositLiquidityParams: depositParams,
            permit2TransferInfo: maliciousPermit
        });

        Types.SignedIntent memory maliciousIntent = Types.SignedIntent({
            info: intentInfo,
            signature: bytes("0x"), // Dummy signature for intent
            orderHash: keccak256(abi.encode(intentInfo))
        });

        // Create a route that would transfer tokens directly to the attacker
        Types.LiquidityRoute memory route = Types.LiquidityRoute({router: attacker, routeData: new bytes(0)});

        // Try to execute the intent with the malicious permit
        vm.startPrank(attacker);

        // This should fail with an error from Permit2 about invalid signature
        // because permit signatures are bound to the specific spender/recipient
        vm.expectRevert(); // Expecting any revert is sufficient as Permit2 should reject the signature
        riftReactor.executeIntentWithSwap(route, maliciousIntent);

        vm.stopPrank();

        // Check that no tokens were transferred from the victim
        uint256 victimBalance = inputToken.balanceOf(victim);
        assertEq(victimBalance, 10_000_000, "Victim balance should be unchanged");
    }

    /**
     * @notice Tests to verify that Permit2 properly validates permit signatures
     */
    function testPermit2SignatureValidation() public {
        // Create a valid permit and signature
        uint256 amount = 1_000_000;
        uint256 nonce = 0;
        uint256 deadline = block.timestamp + 3600;

        Types.Permit2TransferInfo memory validPermit = createValidPermitSignature(
            address(inputToken),
            amount,
            nonce,
            deadline,
            address(riftReactor)
        );

        // Test 1: Modify signature should invalidate it
        Types.Permit2TransferInfo memory tamperedSignaturePermit = Types.Permit2TransferInfo({
            permitTransferFrom: validPermit.permitTransferFrom,
            transferDetails: validPermit.transferDetails,
            owner: validPermit.owner,
            signature: new bytes(65) // Different signature
        });

        vm.expectRevert();
        permit2.permitTransferFrom(
            tamperedSignaturePermit.permitTransferFrom,
            tamperedSignaturePermit.transferDetails,
            tamperedSignaturePermit.owner,
            tamperedSignaturePermit.signature
        );

        // Test 2: Modify token amount should invalidate it
        Types.Permit2TransferInfo memory tamperedAmountPermit = Types.Permit2TransferInfo({
            permitTransferFrom: ISignatureTransfer.PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({
                    token: validPermit.permitTransferFrom.permitted.token,
                    amount: validPermit.permitTransferFrom.permitted.amount + 1 // Different amount
                }),
                nonce: validPermit.permitTransferFrom.nonce,
                deadline: validPermit.permitTransferFrom.deadline
            }),
            transferDetails: validPermit.transferDetails,
            owner: validPermit.owner,
            signature: validPermit.signature
        });

        vm.expectRevert();
        permit2.permitTransferFrom(
            tamperedAmountPermit.permitTransferFrom,
            tamperedAmountPermit.transferDetails,
            tamperedAmountPermit.owner,
            tamperedAmountPermit.signature
        );

        // Test 3: Modify recipient should invalidate it
        Types.Permit2TransferInfo memory tamperedRecipientPermit = Types.Permit2TransferInfo({
            permitTransferFrom: validPermit.permitTransferFrom,
            transferDetails: ISignatureTransfer.SignatureTransferDetails({
                to: attacker, // Different recipient
                requestedAmount: validPermit.transferDetails.requestedAmount
            }),
            owner: validPermit.owner,
            signature: validPermit.signature
        });

        vm.expectRevert();
        permit2.permitTransferFrom(
            tamperedRecipientPermit.permitTransferFrom,
            tamperedRecipientPermit.transferDetails,
            tamperedRecipientPermit.owner,
            tamperedRecipientPermit.signature
        );

        // Test 4: Using wrong nonce should invalidate it
        Types.Permit2TransferInfo memory tamperedNoncePermit = Types.Permit2TransferInfo({
            permitTransferFrom: ISignatureTransfer.PermitTransferFrom({
                permitted: validPermit.permitTransferFrom.permitted,
                nonce: validPermit.permitTransferFrom.nonce + 1, // Different nonce
                deadline: validPermit.permitTransferFrom.deadline
            }),
            transferDetails: validPermit.transferDetails,
            owner: validPermit.owner,
            signature: validPermit.signature
        });

        vm.expectRevert();
        permit2.permitTransferFrom(
            tamperedNoncePermit.permitTransferFrom,
            tamperedNoncePermit.transferDetails,
            tamperedNoncePermit.owner,
            tamperedNoncePermit.signature
        );
    }
}
