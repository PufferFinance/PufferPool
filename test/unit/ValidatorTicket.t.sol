// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferPoolStorage } from "puffer/struct/PufferPoolStorage.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { ERC20 } from "openzeppelin/token/ERC20/ERC20.sol";
import { LibGuardianMessages } from "puffer/LibGuardianMessages.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { Unauthorized } from "puffer/Errors.sol";

contract Mock is ERC20 {
    constructor() ERC20("mock", "mock") {
        _mint(msg.sender, 1_000_000 ether);
    }
}

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

    // Test setup
    function testSetup() public {
        assertEq(validatorTicket.name(), "ValidatorTicket");
        assertEq(validatorTicket.symbol(), "VT");
    }

    // Test that only guardians can call setSendOnReceive
    function testSetSendOnReceive() public {
        vm.expectRevert(Unauthorized.selector);
        validatorTicket.setSendOnReceive(1 ether);
        vm.prank(address(3));
        validatorTicket.setSendOnReceive(1 ether);
    }

    // Test that only guardians can call setTreasuryFee
    function testSetTreasuryFee() public {
        vm.expectRevert(Unauthorized.selector);
        validatorTicket.setTreasuryFee(1 ether);
        vm.prank(address(3));
        validatorTicket.setTreasuryFee(1 ether);
    }

    // Test that only the oracle can call setMintPrice
    function testSetMintPrice() public {
        vm.expectRevert(Unauthorized.selector);
        validatorTicket.setMintPrice(1 ether);
        vm.prank(address(1));
        validatorTicket.setMintPrice(1 ether);
    }

    // Test minting and check balances
    function testMint() public {
        vm.deal(rewardsRecipient, 1 ether);

        vm.prank(address(1));
        validatorTicket.setMintPrice(1 ether);
        vm.startPrank(address(3));
        validatorTicket.setSendOnReceive(0);
        validatorTicket.setTreasuryFee(0);
        vm.stopPrank();

        vm.prank(rewardsRecipient);
        validatorTicket.mint{value: 1 ether}();

        assertEq(validatorTicket.balanceOf(rewardsRecipient), 1);
        assertEq(validatorTicket.balanceOf(address(validatorTicket)), 0);
        assertEq(address(validatorTicket).balance, 1 ether);
    }

    function testMintAndSetOnReceiveFee() public {
        vm.deal(rewardsRecipient, 1 ether);
        vm.deal(address(validatorTicket), 1 ether);

        vm.prank(address(1));
        validatorTicket.setMintPrice(1 ether);
        vm.startPrank(address(3));
        validatorTicket.setSendOnReceive(1 ether);
        validatorTicket.setTreasuryFee(0);
        vm.stopPrank();

        vm.prank(rewardsRecipient);
        validatorTicket.mint{value: 1 ether}();

        assertEq(validatorTicket.balanceOf(rewardsRecipient), 1);
        assertEq(validatorTicket.balanceOf(address(validatorTicket)), 0);
        assertEq(address(validatorTicket).balance, 1990000000000000000);
        assertEq(address(2).balance, 10**16);
    }

    // Test distribute function
    function testDistribute() public {
        vm.deal(address(validatorTicket), 1 ether);

        vm.startPrank(address(3));
        validatorTicket.setTreasuryFee(1 ether);

        validatorTicket.distribute();
        vm.stopPrank();

        // Treasury should get 10**16 (1%)
        // Guardians should get 10 ** 18 - 10 ** 16 (99%)
        assertEq(address(4).balance, 10**16);
        assertEq(address(3).balance, 10**18 - 10**16);
    }
}
