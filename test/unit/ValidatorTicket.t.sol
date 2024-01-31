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

    // Test that only guardians can call setSendOnReceive
    function testSetSendOnReceive() public {
        vm.expectRevert();
        validatorTicket.setSendOnReceive(1 ether);
        vm.prank(DAO);
        validatorTicket.setSendOnReceive(1 ether);
    }

/*
    function test_funds_splitting() public {
        uint256 vtPrice = validatorTicket.getValidatorTicketPrice();

        uint256 amount = vtPrice * 2000; // 20000 VTs is 20 ETH
        vm.deal(address(this), amount);

        address treasury = validatorTicket.TREASURY();

        assertEq(validatorTicket.balanceOf(address(this)), 0, "should start with 0");
        assertEq(validatorTicket.balanceOf(treasury), 0, "should start with 0");

        validatorTicket.purchaseValidatorTicket{ value: amount }(address(this));

        // 0.5% from 20 ETH is 0.1 ETH
        assertEq(validatorTicket.getGuardiansBalance(), 0.1 ether, "guardians balance");
        // 5% from 20 ETH is 1 ETH
        assertEq(treasury.balance, 1 ether, "treasury should get 1 ETH for 100 VTs");
    }

    function test_overflow_protocol_fee_rate() public {
        vm.startPrank(DAO);
        vm.expectRevert(bytes4(hex"35278d12")); // Overflow() selector 0x35278d12
        validatorTicket.setProtocolFeeRate(20 * FixedPointMathLib.WAD); // should revert because max fee is 18.44% (uint64)
    }

    function test_change_protocol_fee_rate() public {
        vm.startPrank(DAO);

        uint256 newFeeRate = 15 * FixedPointMathLib.WAD;

        vm.expectEmit(true, true, true, true);
        emit ValidatorTicket.ProtocolFeeChanged(5 * FixedPointMathLib.WAD, newFeeRate);
        validatorTicket.setProtocolFeeRate(newFeeRate);

        assertEq(validatorTicket.getProtocolFeeRate(), newFeeRate, "updated");
    }
    */
}
