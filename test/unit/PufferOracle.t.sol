// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { TestHelper } from "../helpers/TestHelper.sol";
import { Address } from "openzeppelin/utils/Address.sol";
import { IPufferOracle } from "pufETH/interface/IPufferOracle.sol";
import { PufferOracle } from "puffer/PufferOracle.sol";
import { PufferOracleV2 } from "puffer/PufferOracleV2.sol";
import { IAccessManaged } from "openzeppelin/access/manager/IAccessManaged.sol";


contract PufferOracleTest is TestHelper {
    using Address for address;
    using Address for address payable;

    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();

        //@todo Important note:
        // In this unit tests, we are using the simplified PufferOracle smart contract (V1) but
        // use the PufferOracleV2 interface to interact with it. This is because the PufferOracleV2
        // interface is the one that is used by the ValidatorTicket smart contract. 
        pufferOracle = PufferOracleV2(address(new PufferOracle(address(accessManager))));
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
        pufferOracle.setMintPrice(uint56(0.01 ether));
        vm.expectRevert(IAccessManaged.AccessManagedUnauthorized.selector); // not working
        vm.stopPrank();
    }

    function test_set_mint_price_0_reverts() public {
        vm.startPrank(DAO);
        pufferOracle.setMintPrice(uint56(0 ether));
        vm.expectRevert(IPufferOracle.InvalidValidatorTicketPrice.selector); // failing from AccessManagedUnauthorized
        vm.stopPrank();
    }

    function test_set_mint_price_exceeds_maximum_reverts(uint256 price) public {
        vm.startPrank(DAO);
        pufferOracle.setMintPrice(uint56(0.1 ether + price));
        vm.expectRevert(IPufferOracle.InvalidValidatorTicketPrice.selector); // failing from AccessManagedUnauthorized
        vm.stopPrank();
    }

    function test_set_mint_price_succeeds(uint256 price) public {
        price = bound(price, 0, 0.1 ether);
        vm.startPrank(DAO);
        pufferOracle.setMintPrice(uint56(price));
        vm.expectRevert(IPufferOracle.InvalidValidatorTicketPrice.selector); // failing from AccessManagedUnauthorized
        assertEq(pufferOracle.getValidatorTicketPrice(), price, "price");
        vm.stopPrank();
    }

}
