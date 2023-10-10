// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { TestBase } from "../TestBase.t.sol";
import { BeaconMock } from "../mocks/BeaconMock.sol";
import { console } from "forge-std/console.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferProtocolStorage } from "puffer/PufferProtocolStorage.sol";

contract GuardianModuleTest is TestHelper, TestBase {
    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();
        _skipDefaultFuzzAddresses();
    }

    function testRave() public {
        _testRave();
    }
}
