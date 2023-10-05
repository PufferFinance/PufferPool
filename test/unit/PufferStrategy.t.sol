// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferProtocolMockUpgrade } from "../mocks/PufferProtocolMockUpgrade.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { TestBase } from "../TestBase.t.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { BeaconMock } from "../mocks/BeaconMock.sol";
import { Status } from "puffer/struct/Status.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferStrategy } from "puffer/PufferStrategy.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";

contract PufferStrategyUpgrade {
    function getMagicValue() external pure returns (uint256) {
        return 1337;
    }
}

contract PufferStrategyTest is TestHelper, TestBase {
    function setUp() public override {
        super.setUp();

        vm.deal(address(this), 1000 ether);

        // Setup roles
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = UpgradeableBeacon.upgradeTo.selector;

        // For simplicity transfer ownership to this contract
        vm.startPrank(_broadcaster);
        accessManager.setTargetFunctionRole(pufferProtocol.PUFFER_STRATEGY_BEACON(), selectors, ROLE_ID_DAO);
        accessManager.grantRole(ROLE_ID_DAO, address(this), 0);
        vm.stopPrank();

        _skipDefaultFuzzAddresses();

        fuzzedAddressMapping[address(pufferProtocol)] = true;
    }

    function testGetEigenPod() public {
        assertTrue(
            PufferStrategy(payable(pufferProtocol.getDefaultStrategy())).getEigenPod() != address(0), "get eigenpod"
        );
    }

    function testBeaconUpgrade() public {
        address strategyBeacon = pufferProtocol.PUFFER_STRATEGY_BEACON();

        (bool success,) =
            pufferProtocol.getDefaultStrategy().call(abi.encodeCall(PufferStrategyUpgrade.getMagicValue, ()));
        assertTrue(!success, "should not succeed");

        PufferStrategyUpgrade upgrade = new PufferStrategyUpgrade();

        accessManager.execute(strategyBeacon, abi.encodeCall(UpgradeableBeacon.upgradeTo, address(upgrade)));

        (bool s, bytes memory data) =
            pufferProtocol.getDefaultStrategy().call(abi.encodeCall(PufferStrategyUpgrade.getMagicValue, ()));
        assertTrue(s, "should succeed");
        assertEq(abi.decode(data, (uint256)), 1337, "got the number");
    }
}
