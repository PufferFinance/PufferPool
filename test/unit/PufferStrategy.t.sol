// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferProtocolMockUpgrade } from "../mocks/PufferProtocolMockUpgrade.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { BeaconMock } from "../mocks/BeaconMock.sol";
import { Status } from "puffer/struct/Status.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferStrategy } from "puffer/PufferStrategy.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { ROLE_ID_DAO } from "script/SetupAccess.s.sol";

contract PufferStrategyUpgrade {
    function getMagicValue() external pure returns (uint256) {
        return 1337;
    }
}

contract PufferStrategyTest is TestHelper {
    function setUp() public override {
        super.setUp();

        vm.deal(address(this), 1000 ether);

        _skipDefaultFuzzAddresses();

        fuzzedAddressMapping[address(pufferProtocol)] = true;
    }

    function testBeaconUpgrade() public {
        address strategyBeacon = pufferProtocol.PUFFER_STRATEGY_BEACON();

        vm.startPrank(DAO);
        pufferProtocol.createPufferStrategy(bytes32("DEGEN"));
        vm.stopPrank();

        // No restaking is a custom default strategy (non beacon upgradeable)
        (bool success,) = pufferProtocol.getStrategyAddress(bytes32("DEGEN")).call(
            abi.encodeCall(PufferStrategyUpgrade.getMagicValue, ())
        );

        assertTrue(!success, "should not succeed");

        PufferStrategyUpgrade upgrade = new PufferStrategyUpgrade();

        vm.startPrank(DAO);
        accessManager.execute(strategyBeacon, abi.encodeCall(UpgradeableBeacon.upgradeTo, address(upgrade)));
        vm.stopPrank();

        (bool s, bytes memory data) = pufferProtocol.getStrategyAddress(bytes32("DEGEN")).call(
            abi.encodeCall(PufferStrategyUpgrade.getMagicValue, ())
        );
        assertTrue(s, "should succeed");
        assertEq(abi.decode(data, (uint256)), 1337, "got the number");
    }
}
