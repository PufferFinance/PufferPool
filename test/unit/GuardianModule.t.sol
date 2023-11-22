// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { TestHelper } from "../helpers/TestHelper.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { Guardian2RaveEvidence } from "../helpers/GuardiansRaveEvidence.sol";
import { Unauthorized } from "puffer/Errors.sol";

contract GuardianModuleTest is TestHelper {
    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();
        _skipDefaultFuzzAddresses();
    }

    function testRave() public {
        _deployContractAndSetupGuardians();
    }

    function testRotateGuardianKeyFromNonGuardianReverts() public {
        RaveEvidence memory evidence;
        vm.expectRevert(Unauthorized.selector);
        guardianModule.rotateGuardianKey(0, new bytes(55), evidence);
    }

    function testRoateGuardianToInvalidPubKeyReverts() public {
        RaveEvidence memory evidence;

        vm.startPrank(guardian1);

        vm.expectRevert(IGuardianModule.InvalidECDSAPubKey.selector);
        guardianModule.rotateGuardianKey(0, new bytes(55), evidence);
    }

    function testAddGuardian(address guardian) public assumeEOA(guardian) {
        vm.startPrank(DAO);

        // Must not be a guardian already
        vm.assume(!guardianModule.isGuardian(guardian));

        vm.expectEmit(true, true, true, true);
        emit IGuardianModule.GuardianAdded(guardian);
        guardianModule.addGuardian(guardian);
    }

    function testRemoveGuardian(address guardian) public {
        testAddGuardian(guardian);

        vm.expectEmit(true, true, true, true);
        emit IGuardianModule.GuardianRemoved(guardian);
        guardianModule.removeGuardian(guardian);
    }

    function testSplitFunds() public {
        vm.deal(address(guardianModule), 1 ether);

        guardianModule.splitGuardianFunds();

        assertEq(guardian1.balance, guardian2.balance, "guardian balances");
        assertEq(guardian1.balance, guardian3.balance, "guardian balances");
    }

    function testChangeThreshold() public {
        vm.startPrank(DAO);

        vm.expectEmit(true, true, true, true);
        emit IGuardianModule.ThresholdChanged(1, 2);
        guardianModule.changeThreshold(2);
    }

    function testChangeThresholdReverts() public {
        vm.startPrank(DAO);

        // We have 3 guardians, try setting threshold to 5
        vm.expectRevert();
        guardianModule.changeThreshold(5);
    }

    function testRoateGuardianKeyWithInvalidRaveReverts() public {
        Guardian2RaveEvidence guardian2Rave = new Guardian2RaveEvidence();

        vm.startPrank(guardian1);

        RaveEvidence memory rave = RaveEvidence({
            report: guardian2Rave.report(),
            signature: guardian2Rave.sig(),
            leafX509CertDigest: keccak256(guardian2Rave.signingCert())
        });

        vm.expectRevert(IGuardianModule.InvalidRAVE.selector);
        guardianModule.rotateGuardianKey(1, guardian3EnclavePubKey, rave);
    }
}
