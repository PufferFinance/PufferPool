// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { GuardianModule } from "puffer/GuardianModule.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { Test } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { PufferServiceManager } from "puffer/PufferServiceManager.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { DeployGuardians } from "scripts/1_DeployGuardians.s.sol";
import { BaseScript } from "scripts/BaseScript.s.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { DeployPuffer } from "scripts/DeployPuffer.s.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IEnclaveVerifier } from "puffer/interface/IEnclaveVerifier.sol";
import { Guardian1RaveEvidence, Guardian2RaveEvidence, Guardian3RaveEvidence } from "./GuardiansRaveEvidence.sol";
import { console } from "forge-std/console.sol";

contract TestHelper is Test, BaseScript {
    // In our test setup we have 3 guardians and 3 guaridan enclave keys
    uint256[] guardiansEnclavePks;
    address guardian1;
    uint256 guardian1SK;
    address guardian2;
    uint256 guardian2SK;
    address guardian3;
    uint256 guardian3SK;
    address guardian1Enclave;
    uint256 guardian1SKEnclave;
    // PubKey is hardcoded because we are creating guardian enclaves deterministically
    bytes guardian1EnclavePubKey =
        hex"048289b999a1a6bc0cc6550ea018d03adee9bfeae6441e53e2e5eed22232a2b8f2d87cf1619c263971a6ada43f7310f37f473de7262ab63778fe3a859c68dc2e27";
    address guardian2Enclave;
    uint256 guardian2SKEnclave;
    bytes guardian2EnclavePubKey =
        hex"0440ba2fa6602bdb09e40d8b400b0c82124c14c8666659c0c78d8e474f3e230d92597cd4811484e1a15d6886745ed6d3fbde7e66f1376e396d8d4e8fa67458a140";
    address guardian3Enclave;
    uint256 guardian3SKEnclave;
    bytes guardian3EnclavePubKey =
        hex"049777a708d71e0b211eff7d44acc9d81be7bbd1bffdc14f60e784c86b64037c745b82cc5d9da0e93dd96d2fb955c32239b2d1d56a456681d4cef88bd603b9b407";

    PufferPool pool;
    PufferServiceManager serviceManager;
    WithdrawalPool withdrawalPool;
    UpgradeableBeacon beacon;

    Safe guardiansSafe;
    GuardianModule module;

    function setUp() public virtual {
        // Create Guardian wallets
        (guardian1, guardian1SK) = makeAddrAndKey("guardian1");
        (guardian1Enclave, guardian1SKEnclave) = makeAddrAndKey("guardian1enclave");
        guardiansEnclavePks.push(guardian1SKEnclave);
        (guardian2, guardian2SK) = makeAddrAndKey("guardian2");
        (guardian2Enclave, guardian2SKEnclave) = makeAddrAndKey("guardian2enclave");
        guardiansEnclavePks.push(guardian2SKEnclave);
        (guardian3, guardian3SK) = makeAddrAndKey("guardian3");
        (guardian3Enclave, guardian3SKEnclave) = makeAddrAndKey("guardian3enclave");
        guardiansEnclavePks.push(guardian3SKEnclave);

        address[] memory guardians = new address[](3);
        guardians[0] = guardian1;
        guardians[1] = guardian2;
        guardians[2] = guardian3;

        // 1. Deploy guardians safe
        (guardiansSafe, module) = new DeployGuardians().run(guardians, 1);

        (serviceManager, pool) = new DeployPuffer().run();

        withdrawalPool = WithdrawalPool(serviceManager.getWithdrawalPool());

        vm.label(address(pool), "PufferPool");
        vm.label(address(serviceManager), "PufferServiceManager");
    }

    // Internal function to create guardian account and register enclave addresses
    // function _createGuardians() internal returns (Safe, address[] memory) {
    //     // Register 3 guardians
    //     address[] memory owners = new address[](3);
    //     owners[0] = guardian1;
    //     owners[1] = guardian2;
    //     owners[2] = guardian3;

    //     bytes memory data = abi.encodeCall(GuardianModule.enableMyself, ());

    //     Safe guardianAccount =
    //         pool.createGuardianAccount({ guardiansWallets: owners, threshold: owners.length, data: data });

    //     // Assert 3 guardians
    //     assertTrue(guardianAccount.isOwner(owners[0]), "bad owner 1");
    //     assertTrue(guardianAccount.isOwner(owners[1]), "bad owner 2");
    //     assertTrue(guardianAccount.isOwner(owners[2]), "bad owner 3");
    //     assertEq(guardianAccount.getThreshold(), 3, "threshold");

    //     GuardianModule module = pool.getGuardianModule();
    //     assertEq(address(module.pool()), address(pool), "module pool address is wrong");

    //     vm.expectRevert(IPufferPool.GuardiansAlreadyExist.selector);
    //     pool.createGuardianAccount({ guardiansWallets: owners, threshold: owners.length, data: data });

    //     Guardian1RaveEvidence guardian1Rave = new Guardian1RaveEvidence();
    //     Guardian2RaveEvidence guardian2Rave = new Guardian2RaveEvidence();
    //     Guardian3RaveEvidence guardian3Rave = new Guardian3RaveEvidence();

    //     // mrenclave and mrsigner are the same for all evidences
    //     pool.setGuardianEnclaveMeasurements(guardian1Rave.mrenclave(), guardian1Rave.mrsigner());

    //     // Add a valid certificate to verifier
    //     IEnclaveVerifier verifier = pool.getEnclaveVerifier();
    //     verifier.addLeafX509(guardian1Rave.signingCert());

    //     require(keccak256(guardian1EnclavePubKey) == keccak256(guardian1Rave.payload()), "pubkeys dont match");

    //     // Register enclave keys for guardians
    //     vm.startPrank(owners[0]);
    //     module.rotateGuardianKey(
    //         address(guardianAccount),
    //         0,
    //         guardian1EnclavePubKey,
    //         RaveEvidence({
    //             report: guardian1Rave.report(),
    //             signature: guardian1Rave.sig(),
    //             leafX509CertDigest: keccak256(guardian1Rave.signingCert())
    //         })
    //     );
    //     vm.stopPrank();

    //     vm.startPrank(owners[1]);
    //     module.rotateGuardianKey(
    //         address(guardianAccount),
    //         0,
    //         guardian2EnclavePubKey,
    //         RaveEvidence({
    //             report: guardian2Rave.report(),
    //             signature: guardian2Rave.sig(),
    //             leafX509CertDigest: keccak256(guardian2Rave.signingCert())
    //         })
    //     );
    //     vm.stopPrank();

    //     vm.startPrank(owners[2]);
    //     module.rotateGuardianKey(
    //         address(guardianAccount),
    //         0,
    //         guardian3EnclavePubKey,
    //         RaveEvidence({
    //             report: guardian3Rave.report(),
    //             signature: guardian3Rave.sig(),
    //             leafX509CertDigest: keccak256(guardian3Rave.signingCert())
    //         })
    //     );
    //     vm.stopPrank();

    //     assertTrue(
    //         module.isGuardiansEnclaveAddress(payable(address(guardianAccount)), owners[0], guardian1Enclave),
    //         "bad enclave address"
    //     );
    //     assertTrue(
    //         module.isGuardiansEnclaveAddress(payable(address(guardianAccount)), owners[1], guardian2Enclave),
    //         "bad enclave address"
    //     );
    //     assertTrue(
    //         module.isGuardiansEnclaveAddress(payable(address(guardianAccount)), owners[2], guardian3Enclave),
    //         "bad enclave address"
    //     );

    //     return (guardianAccount, owners);
    // }
}
