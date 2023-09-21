// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferServiceManager } from "puffer/PufferServiceManager.sol";
import { DeployPuffer } from "scripts/DeployPuffer.s.sol";
import { PufferServiceManagerMockUpgrade } from "./mocks/PufferServiceManagerMockUpgrade.sol";
import { TestHelper } from "./helpers/TestHelper.sol";
import { EnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { TestBase } from "./TestBase.t.sol";

contract PufferServiceManagerTest is TestHelper, TestBase {
    function setUp() public override {
        super.setUp();

        // For simplicity transfer ownership to this contract
        vm.prank(_broadcaster);
        serviceManager.transferOwnership(address(this));

        _skipDefaultFuzzAddresses();

        fuzzedAddressMapping[address(serviceManager)] = true;
    }

    function testSetProtocolFeeRate() public {
        uint256 rate = 20 * FixedPointMathLib.WAD;
        serviceManager.setProtocolFeeRate(rate); // 20%
        assertEq(serviceManager.getProtocolFeeRate(), rate, "new rate");
    }

    // Tests setter for guardian enclave measurements
    function testGuardianEnclaveMeasurements(bytes32 mrsigner, bytes32 mrenclave) public {
        serviceManager.setGuardianEnclaveMeasurements(mrsigner, mrenclave);
        (bytes32 ms, bytes32 me) = serviceManager.getGuardianEnclaveMeasurements();
        assertTrue(mrsigner == ms, "mrsigner guardian");
        assertTrue(mrenclave == me, "mrenclave guardian");
    }

    // Test smart contract upgradeability (UUPS)
    function testUpgrade() public {
        vm.expectRevert();
        uint256 result = PufferServiceManagerMockUpgrade(payable(address(pool))).returnSomething();

        PufferServiceManagerMockUpgrade newImplementation = new PufferServiceManagerMockUpgrade(address(beacon));
        serviceManager.upgradeTo(address(newImplementation));

        result = PufferServiceManagerMockUpgrade(payable(address(serviceManager))).returnSomething();

        assertEq(result, 1337);
    }

    // // Pause
    // function testPause() public {
    //     assertEq(serviceManager.paused(), false, "!paused");
    //     serviceManager.pause();
    //     assertEq(serviceManager.paused(), true, "paused");
    // }

    // // Resume
    // function testResume() public {
    //     serviceManager.pause();
    //     assertEq(serviceManager.paused(), true, "paused");
    //     serviceManager.resume();
    //     assertEq(serviceManager.paused(), false, "resunmed");
    // }

    // Tests setter for enclave measurements
    function testSetNodeEnclaveMeasurements(bytes32 mrsigner, bytes32 mrenclave) public {
        serviceManager.setNodeEnclaveMeasurements(mrsigner, mrenclave);
        (bytes32 ms, bytes32 me) = serviceManager.getNodeEnclaveMeasurements();
        assertTrue(mrsigner == ms, "mrsigner");
        assertTrue(mrenclave == me, "mrenclave");
    }
}
