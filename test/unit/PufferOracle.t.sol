// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { TestHelper } from "../helpers/TestHelper.sol";
import { Address } from "openzeppelin/utils/Address.sol";
import { IPufferOracle } from "pufETH/interface/IPufferOracle.sol";
import { PufferOracle } from "puffer/PufferOracle.sol";
import { PufferOracleV2 } from "puffer/PufferOracleV2.sol";
import { IAccessManaged } from "openzeppelin/access/manager/IAccessManaged.sol";
import { ROLE_ID_DAO } from "pufETHScript/Roles.sol";

/**
 * @dev Test for the simple PufferOracle smart contract
 */
contract PufferOracleTest is TestHelper {
    using Address for address;
    using Address for address payable;

    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();

        // Replace the PufferOracleV2 deployment with this simple PufferOracle
        pufferOracle = PufferOracleV2(address(new PufferOracle(address(accessManager))));

        // Setup Access for the new PufferOracle
        bytes4[] memory daoSelectors = new bytes4[](1);
        daoSelectors[0] = PufferOracle.setMintPrice.selector;
        vm.prank(_broadcaster);
        accessManager.setTargetFunctionRole(address(pufferOracle), daoSelectors, ROLE_ID_DAO);

        _skipDefaultFuzzAddresses();
    }

    function test_setup() public {
        assertEq(pufferOracle.getValidatorTicketPrice(), 0.01 ether, "price");
        assertEq(pufferOracle.getLockedEthAmount(), 0, "locked");
        assertEq(pufferOracle.isOverBurstThreshold(), false, "burst");
    }

    function test_mint_price_is_restricted() public {
        address alice = makeAddr("alice");
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, alice));
        pufferOracle.setMintPrice(0.01 ether);
    }

    function test_set_mint_price_0_reverts() public {
        vm.startPrank(DAO);
        vm.expectRevert(IPufferOracle.InvalidValidatorTicketPrice.selector);
        pufferOracle.setMintPrice(0);
    }

    function test_set_mint_price_exceeds_maximum_reverts(uint256 price) public {
        vm.startPrank(DAO);
        price = bound(price, (0.1 ether + 1), type(uint256).max);
        vm.expectRevert(IPufferOracle.InvalidValidatorTicketPrice.selector);
        pufferOracle.setMintPrice(price);
    }

    function test_set_mint_price_succeeds(uint256 price) public {
        price = bound(price, 1, 0.1 ether);
        vm.startPrank(DAO);
        uint256 priceBefore = pufferOracle.getValidatorTicketPrice();
        vm.expectEmit(true, true, true, true);
        emit IPufferOracle.ValidatorTicketMintPriceUpdated(priceBefore, price);
        pufferOracle.setMintPrice(price);
        assertEq(pufferOracle.getValidatorTicketPrice(), price, "price");
    }
}
