// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Safe } from "safe-contracts/Safe.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { Guardian2RaveEvidence } from "../helpers/GuardiansRaveEvidence.sol";

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
        vm.expectRevert(IGuardianModule.Unauthorized.selector);
        module.rotateGuardianKey(0, new bytes(55), evidence);
    }

    function testRoateGuardianToInvalidPubKeyReverts() public {
        RaveEvidence memory evidence;

        vm.startPrank(guardian1);

        vm.expectRevert(IGuardianModule.InvalidECDSAPubKey.selector);
        module.rotateGuardianKey(0, new bytes(55), evidence);
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
        module.rotateGuardianKey(1, guardian3EnclavePubKey, rave);
    }
}
