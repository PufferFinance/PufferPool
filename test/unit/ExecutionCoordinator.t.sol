// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { TestHelper } from "../helpers/TestHelper.sol";
import { PufferOracle } from "puffer/PufferOracle.sol";
import { ExecutionCoordinator } from "puffer/ExecutionCoordinator.sol";
import { ROLE_ID_OPERATIONS_PAYMASTER, ROLE_ID_OPERATIONS_MULTISIG } from "pufETHScript/Roles.sol";

contract ExecutionCoordinatorTest is TestHelper {
    function setUp() public override {
        super.setUp();

        vm.prank(_broadcaster);
        accessManager.grantRole(ROLE_ID_OPERATIONS_PAYMASTER, address(this), 0);

        // Set the initial price to 1 ETH
        vm.prank(DAO);
        pufferOracle.setMintPrice(1 ether);
    }

    function test_setup() public {
        assertEq(executionCoordinator.getPriceChangeToleranceBps(), 500, "5% is default");
        assertEq(pufferOracle.getLockedEthAmount(), 0, "locked");
        assertEq(pufferOracle.isOverBurstThreshold(), false, "burst");
    }

    function test_vt_price_change_reverts() public {
        // This contract is a 'paymaster', but the price change is too big
        vm.expectRevert(ExecutionCoordinator.InvalidPrice.selector);
        executionCoordinator.setValidatorTicketMintPrice(2 ether);
    }

    function test_vt_price_works() public {
        executionCoordinator.setValidatorTicketMintPrice(1.01 ether);
        executionCoordinator.setValidatorTicketMintPrice(1.02 ether);
        executionCoordinator.setValidatorTicketMintPrice(1.03 ether);
        executionCoordinator.setValidatorTicketMintPrice(1.04 ether);
        executionCoordinator.setValidatorTicketMintPrice(1.05 ether);
    }

    function test_vt_price_zero() public {
        // Set the initial price to 1 wei
        vm.prank(DAO);
        pufferOracle.setMintPrice(1);

        // Zero reverts
        vm.expectRevert(ExecutionCoordinator.InvalidPrice.selector);
        executionCoordinator.setValidatorTicketMintPrice(0);
    }

    function test_percentage_change() public {
        vm.expectRevert();
        pufferOracle.setMintPrice(2 ether);

        vm.prank(_broadcaster);
        accessManager.grantRole(ROLE_ID_OPERATIONS_MULTISIG, address(this), 0);

        executionCoordinator.setPriceChangeToleranceBps(10000);

        // 1 -> 2 eth works
        executionCoordinator.setValidatorTicketMintPrice(2 ether);
    }
}
