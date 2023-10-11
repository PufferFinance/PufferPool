// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Safe } from "safe-contracts/Safe.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { TestBase } from "../TestBase.t.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";

contract GuardianModuleTest is TestHelper, TestBase {
    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();
        _skipDefaultFuzzAddresses();
    }

    function testRave() public {
        _testRave();
    }

    function testRotateGuardianKeyFromNonGuardianReverts() public {
        RaveEvidence memory evidence;
        vm.expectRevert(IGuardianModule.Unauthorized.selector);
        module.rotateGuardianKey(0, new bytes(55), evidence);
    }
}
