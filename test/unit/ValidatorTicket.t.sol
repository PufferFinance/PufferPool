// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { Address } from "openzeppelin/utils/Address.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";

contract ValidatorTicketTest is TestHelper {
    using ECDSA for bytes32;
    using Address for address;
    using Address for address payable;

    address rewardsRecipient = makeAddr("rewardsRecipient");

    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();
        _skipDefaultFuzzAddresses();
    }

    function test_setup() public {
        assertEq(validatorTicket.name(), "Puffer Validator Ticket");
        assertEq(validatorTicket.symbol(), "VT");
        assertEq(validatorTicket.getProtocolFeeRate(), 5 * 1e18, "protocol fee rate"); // 5%
        assertTrue(address(validatorTicket.PUFFER_ORACLE()) != address(0), "oracle");
        assertTrue(validatorTicket.GUARDIAN_MODULE() != address(0), "guardians");
        assertTrue(validatorTicket.PUFFER_VAULT() != address(0), "vault");
    }

    function test_funds_splitting() public {
        uint256 vtPrice = pufferOracle.getValidatorTicketPrice();

        uint256 amount = vtPrice * 2000; // 20000 VTs is 20 ETH
        vm.deal(address(this), amount);

        address treasury = validatorTicket.TREASURY();

        assertEq(validatorTicket.balanceOf(address(this)), 0, "should start with 0");
        assertEq(address(validatorTicket).balance, 0, "treasury balance should start with 0");
        assertEq(address(guardianModule).balance, 0, "guardian balance should start with 0");

        validatorTicket.purchaseValidatorTicket{ value: amount }(address(this));

        // 0.5% from 20 ETH is 0.1 ETH
        assertEq(address(guardianModule).balance, 0.1 ether, "guardians balance");
        // 5% from 20 ETH is 1 ETH
        assertEq(address(validatorTicket).balance, 1 ether, "treasury should get 1 ETH for 100 VTs");
    }

    function test_overflow_protocol_fee_rate() public {
        vm.startPrank(DAO);
        vm.expectRevert();
        validatorTicket.setProtocolFeeRate(20 * 1 ether); // should revert because max fee is 18.44% (uint64)
    }

    function test_change_protocol_fee_rate() public {
        vm.startPrank(DAO);

        uint256 newFeeRate = 15 * 1 ether;

        vm.expectEmit(true, true, true, true);
        emit ValidatorTicket.ProtocolFeeChanged(5 * 1 ether, newFeeRate);
        validatorTicket.setProtocolFeeRate(newFeeRate);

        assertEq(validatorTicket.getProtocolFeeRate(), newFeeRate, "updated");
    }
}
