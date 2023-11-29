// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { TestHelper } from "../helpers/TestHelper.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";

contract PufferModuleUpgrade {
    function getMagicValue() external pure returns (uint256) {
        return 1337;
    }
}

contract PufferModuleTest is TestHelper {
    function setUp() public override {
        super.setUp();

        vm.deal(address(this), 1000 ether);

        _skipDefaultFuzzAddresses();

        fuzzedAddressMapping[address(pufferProtocol)] = true;
    }

    function testBeaconUpgrade() public {
        address moduleBeacon = moduleFactory.PUFFER_MODULE_BEACON();

        vm.startPrank(DAO);
        pufferProtocol.createPufferModule(bytes32("DEGEN"));
        vm.stopPrank();

        // No restaking is a custom default module (non beacon upgradeable)
        (bool success,) = pufferProtocol.getModuleAddress(bytes32("DEGEN")).call(
            abi.encodeCall(PufferModuleUpgrade.getMagicValue, ())
        );

        assertTrue(!success, "should not succeed");

        PufferModuleUpgrade upgrade = new PufferModuleUpgrade();

        vm.startPrank(DAO);
        accessManager.execute(moduleBeacon, abi.encodeCall(UpgradeableBeacon.upgradeTo, address(upgrade)));
        vm.stopPrank();

        (bool s, bytes memory data) = pufferProtocol.getModuleAddress(bytes32("DEGEN")).call(
            abi.encodeCall(PufferModuleUpgrade.getMagicValue, ())
        );
        assertTrue(s, "should succeed");
        assertEq(abi.decode(data, (uint256)), 1337, "got the number");
    }
}
