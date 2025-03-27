// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RiftExchange} from "../../src/RiftExchange.sol";
import {RiftReactor} from "../../src/RiftReactor.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Test} from "forge-std/src/Test.sol";
import {SP1MockVerifier} from "sp1-contracts/contracts/src/SP1MockVerifier.sol";
import {MockToken} from "./MockToken.sol";
import {IPermit2, ISignatureTransfer} from "uniswap-permit2/src/interfaces/IPermit2.sol";
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {RiftTest} from "./RiftTest.sol";
import {VaultLib} from "../../src/libraries/VaultLib.sol";

contract RiftReactorMock is RiftReactor, RiftTest {
    constructor(
        bytes32 _mmrRoot,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifier,
        address _feeRouter,
        Types.BlockLeaf memory _tipBlockLeaf,
        address _cbbtc_address,
        address _permit2_adress
    )
        RiftReactor(
            _mmrRoot,
            _depositToken,
            _circuitVerificationKey,
            _verifier,
            _feeRouter,
            _tipBlockLeaf,
            _cbbtc_address,
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
}

contract RiftTestSetup is RiftTest {
    address exchangeOwner = address(0xbeef);
    RiftExchangeExposed public exchange;
    MockToken public mockToken;
    SP1MockVerifier public verifier;

    // address exchangeOwner = address(0xbeef);
    // MockToken public mockToken;
    // MockToken public override mockToken;
    MockToken public cbBTC;
    MockPermit2 public permit2;
    // SP1MockVerifier public override verifier;
    RiftReactorMock public riftReactor;

    function setUp() public virtual override {
        mockToken = new MockToken("Mock Token", "MTK", 6);
        verifier = new SP1MockVerifier();

        Types.MMRProof memory initial_mmr_proof = _generateFakeBlockMMRProofFFI(0);
        cbBTC = new MockToken("Mock cbBTC", "cbBTC", 8);

        riftReactor = new RiftReactorMock({
            _mmrRoot: initial_mmr_proof.mmrRoot,
            _depositToken: address(mockToken),
            _circuitVerificationKey: bytes32(keccak256("circuit verification key")),
            _verifier: address(verifier),
            _feeRouter: address(0xfee),
            _tipBlockLeaf: initial_mmr_proof.blockLeaf,
            _cbbtc_address: address(cbBTC),
            _permit2_adress: address(permit2) // Newly added permit2 address
        });

        mockToken = MockToken(address(riftReactor.DEPOSIT_TOKEN()));

        // Mint tokens to the test contract so it can approve depositBond.
        // Adjust the mint amount as needed.
        mockToken.mint(address(this), 1_000_000);
        cbBTC.mint(address(this), 1_000_000);
    }
}

/**
 * @title MockPermit2
 * @notice Mock implementation of the Permit2 contract for testing
 */
contract MockPermit2 {
    function permitTransferFrom(
        ISignatureTransfer.PermitTransferFrom calldata permit,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata /*signature*/
    ) external {
        // Get the token from the permitted struct
        address token = permit.permitted.token;

        // Check balance and allowance
        uint256 balance = IERC20(token).balanceOf(owner);
        require(balance >= transferDetails.requestedAmount, "Insufficient balance");

        uint256 allowance = IERC20(token).allowance(owner, address(this));
        require(allowance >= transferDetails.requestedAmount, "Insufficient allowance");

        // Perform the transfer
        bool success = IERC20(token).transferFrom(owner, transferDetails.to, transferDetails.requestedAmount);

        require(success, "Transfer failed");
    }
}
