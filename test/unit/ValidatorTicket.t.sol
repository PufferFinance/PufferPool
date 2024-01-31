// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { GuardiansDeployment, PufferProtocolDeployment } from "../../script/DeploymentStructs.sol";
import { Unauthorized } from "puffer/Errors.sol";

contract ValidatorTicketTest is TestHelper {
    using ECDSA for bytes32;
    using SafeTransferLib for address;
    using SafeTransferLib for address payable;

    address rewardsRecipient = makeAddr("rewardsRecipient");

    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();
        _skipDefaultFuzzAddresses();
    }

    function test_setup() public {
        assertEq(validatorTicket.name(), "Validator Ticket");
        assertEq(validatorTicket.symbol(), "VT");
        assertEq(validatorTicket.getSendOnReceiveFee(), 90 * 1e18, "Send on Receive Fee");
        assertTrue(validatorTicket.TREASURY() != address(0), "treasury address");
    }

    // Test that only DAO can call setSendOnReceive
    function testSetSendOnReceive() public {
        vm.expectRevert();
        validatorTicket.setSendOnReceive(1 ether);
        vm.prank(DAO);
        validatorTicket.setSendOnReceive(1 ether);
    }

    // Test that only DAO can call setTreasuryFee
    function testSetTreasuryFee() public {
        vm.expectRevert();
        validatorTicket.setTreasuryFee(1 ether);
        vm.prank(DAO);
        validatorTicket.setTreasuryFee(1 ether);
    }

    // Test that only the oracle can call setMintPrice
    function testSetMintPrice() public {
        vm.expectRevert();
        validatorTicket.setMintPrice(1 ether);
        vm.prank(address(DAO));
        validatorTicket.setMintPrice(1 ether);
    }

    // Test minting and check balances
    function testMint() public {
        vm.deal(rewardsRecipient, 1 ether);

        vm.startPrank(DAO);
        validatorTicket.setMintPrice(1 ether);
        validatorTicket.setSendOnReceive(0);
        validatorTicket.setTreasuryFee(0);
        vm.stopPrank();

        vm.prank(rewardsRecipient);
        validatorTicket.purchaseValidatorTicket{ value: 1 ether }(rewardsRecipient);

        assertEq(validatorTicket.balanceOf(rewardsRecipient), 1);
        assertEq(validatorTicket.balanceOf(address(validatorTicket)), 0);
        assertEq(address(validatorTicket).balance, 1 ether);
    }

    function testMintAndSetOnReceiveFee() public {
        uint256 oldPufferVaultBalance = address(pufferVault).balance;
        vm.deal(rewardsRecipient, 1 ether);
        vm.deal(address(validatorTicket), 1 ether);

        vm.startPrank(DAO);
        validatorTicket.setMintPrice(1 ether);
        validatorTicket.setSendOnReceive(1 ether);
        validatorTicket.setTreasuryFee(0);
        vm.stopPrank();

        vm.prank(rewardsRecipient);
        validatorTicket.purchaseValidatorTicket{ value: 1 ether }(rewardsRecipient);

        assertEq(validatorTicket.balanceOf(rewardsRecipient), 1);
        assertEq(validatorTicket.balanceOf(address(validatorTicket)), 0);
        assertEq(address(validatorTicket).balance, 1990000000000000000);
        assertEq(address(pufferVault).balance, oldPufferVaultBalance + 10 ** 16);
    }

    // Test distribute function
    function testDistribute() public {
        vm.deal(address(validatorTicket), 1 ether);

        vm.startPrank(DAO);
        validatorTicket.setTreasuryFee(1 ether);
        validatorTicket.distribute();
        vm.stopPrank();

        // Treasury should get 10**16 (1%)
        // Guardians should get 10 ** 18 - 10 ** 16 (99%)
        assertEq(address(validatorTicket.TREASURY()).balance, 10 ** 16);
        assertEq(address(guardianModule).balance, 10 ** 18 - 10 ** 16);
    }
}
