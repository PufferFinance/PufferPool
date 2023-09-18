// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferServiceManager } from "puffer/PufferServiceManager.sol";
import { GuardianHelper } from "./helpers/GuardianHelper.sol";
import { TestBase } from "./TestBase.t.sol";

contract PufferPoolTest is GuardianHelper, TestBase {
    PufferServiceManager serviceManager;

    function setUp() public override {
        super.setUp();

        serviceManager = new PufferServiceManager(pool);

        _skipDefaultFuzzAddresses();

        fuzzedAddressMapping[address(serviceManager)] = true;
    }

    // Tests setter for enclave measurements
    function testSetNodeEnclaveMeasurements(bytes32 mrsigner, bytes32 mrenclave) public {
        serviceManager.setNodeEnclaveMeasurements(mrsigner, mrenclave);
        (bytes32 ms, bytes32 me) = serviceManager.getNodeEnclaveMeasurements();
        assertTrue(mrsigner == ms, "mrsigner");
        assertTrue(mrenclave == me, "mrenclave");
    }
}
