// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { GuardianModule } from "puffer/GuardianModule.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { Test } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { BaseScript } from "script/BaseScript.s.sol";
// import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { DeployPuffer } from "script/DeployPuffer.s.sol";
import { DeployGuardians } from "script/1_DeployGuardians.s.sol";
import { SetupAccess } from "script/SetupAccess.s.sol";
import { IEnclaveVerifier } from "puffer/interface/IEnclaveVerifier.sol";
import { Guardian1RaveEvidence, Guardian2RaveEvidence, Guardian3RaveEvidence } from "./GuardiansRaveEvidence.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";

contract TestHelper is Test, BaseScript {
    bytes32 public constant NO_RESTAKING = bytes32("NO_RESTAKING");
    address public constant ADDRESS_ZERO = address(0);
    address public constant ADDRESS_ONE = address(1);
    address public constant ADDRESS_CHEATS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;

    // Addresses that are supposed to be skipped when fuzzing
    mapping(address fuzzedAddress => bool isFuzzed) internal fuzzedAddressMapping;

    // In our test setup we have 3 guardians and 3 guaridan enclave keys
    uint256[] public guardiansEnclavePks;
    address public guardian1;
    uint256 public guardian1SK;
    address public guardian2;
    uint256 public guardian2SK;
    address public guardian3;
    uint256 public guardian3SK;
    address public guardian1Enclave;
    uint256 public guardian1SKEnclave;
    // PubKey is hardcoded because we are creating guardian enclaves deterministically
    bytes public guardian1EnclavePubKey =
        hex"048289b999a1a6bc0cc6550ea018d03adee9bfeae6441e53e2e5eed22232a2b8f2d87cf1619c263971a6ada43f7310f37f473de7262ab63778fe3a859c68dc2e27";
    address public guardian2Enclave;
    uint256 public guardian2SKEnclave;
    bytes public guardian2EnclavePubKey =
        hex"0440ba2fa6602bdb09e40d8b400b0c82124c14c8666659c0c78d8e474f3e230d92597cd4811484e1a15d6886745ed6d3fbde7e66f1376e396d8d4e8fa67458a140";
    address public guardian3Enclave;
    uint256 public guardian3SKEnclave;
    bytes public guardian3EnclavePubKey =
        hex"049777a708d71e0b211eff7d44acc9d81be7bbd1bffdc14f60e784c86b64037c745b82cc5d9da0e93dd96d2fb955c32239b2d1d56a456681d4cef88bd603b9b407";

    PufferPool public pool;
    PufferProtocol public pufferProtocol;
    IWithdrawalPool public withdrawalPool;
    UpgradeableBeacon public beacon;

    Safe public guardiansSafe;
    GuardianModule public module;

    AccessManager public accessManager;
    IEnclaveVerifier public verifier;

    address public DAO = makeAddr("DAO");

    modifier fuzzedAddress(address addr) virtual {
        vm.assume(fuzzedAddressMapping[addr] == false);
        _;
    }

    modifier assumeEOA(address addr) {
        vm.assume(addr.code.length == 0);
        vm.assume(addr != ADDRESS_ZERO);
        vm.assume(addr != ADDRESS_ONE);
        vm.assume(addr != address(2));
        vm.assume(addr != address(3));
        vm.assume(addr != address(4));
        vm.assume(addr != address(5));
        vm.assume(addr != address(6));
        vm.assume(addr != address(7));
        vm.assume(addr != address(8));
        vm.assume(addr != address(9));
        // vm.assumePayable(addr); // don't have it in current foundry version
        vm.assume(addr != 0x000000000000000000636F6e736F6c652e6c6f67); // console address
        _;
    }

    function setUp() public virtual {
        _deployContractAndSetupGuardians();
        _skipDefaultFuzzAddresses();
    }

    function _skipDefaultFuzzAddresses() internal {
        fuzzedAddressMapping[ADDRESS_CHEATS] = true;
        fuzzedAddressMapping[ADDRESS_ZERO] = true;
        fuzzedAddressMapping[ADDRESS_ONE] = true;
        fuzzedAddressMapping[address(withdrawalPool)] = true;
        fuzzedAddressMapping[address(module)] = true;
        fuzzedAddressMapping[address(verifier)] = true;
        fuzzedAddressMapping[address(accessManager)] = true;
        fuzzedAddressMapping[address(guardiansSafe)] = true;
        fuzzedAddressMapping[address(beacon)] = true;
        fuzzedAddressMapping[address(pufferProtocol)] = true;
        fuzzedAddressMapping[address(pool)] = true;
    }

    function _deployContractAndSetupGuardians() public {
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
        (guardiansSafe, module) = new DeployGuardians().run(guardians, 1, "");

        // Deploy puffer protocol
        (pufferProtocol, pool, accessManager) = new DeployPuffer().run();

        // Setup roles and access
        new SetupAccess().run(DAO);

        withdrawalPool = pufferProtocol.getWithdrawalPool();
        verifier = module.ENCLAVE_VERIFIER();

        vm.label(address(pool), "PufferPool");
        vm.label(address(pufferProtocol), "PufferProtocol");

        Guardian1RaveEvidence guardian1Rave = new Guardian1RaveEvidence();
        Guardian2RaveEvidence guardian2Rave = new Guardian2RaveEvidence();
        Guardian3RaveEvidence guardian3Rave = new Guardian3RaveEvidence();

        // mrenclave and mrsigner are the same for all evidences
        vm.startPrank(DAO);
        module.setGuardianEnclaveMeasurements(guardian1Rave.mrenclave(), guardian1Rave.mrsigner());
        vm.stopPrank();

        assertEq(module.getMrenclave(), guardian1Rave.mrenclave(), "mrenclave");
        assertEq(module.getMrsigner(), guardian1Rave.mrsigner(), "mrsigner");

        // Add a valid certificate to verifier
        verifier = module.ENCLAVE_VERIFIER();
        verifier.addLeafX509(guardian1Rave.signingCert());

        require(keccak256(guardian1EnclavePubKey) == keccak256(guardian1Rave.payload()), "pubkeys dont match");

        // Register enclave keys for guardians
        vm.startPrank(guardians[0]);
        module.rotateGuardianKey(
            0,
            guardian1EnclavePubKey,
            RaveEvidence({
                report: guardian1Rave.report(),
                signature: guardian1Rave.sig(),
                leafX509CertDigest: keccak256(guardian1Rave.signingCert())
            })
        );
        vm.stopPrank();

        vm.startPrank(guardians[1]);
        module.rotateGuardianKey(
            0,
            guardian2EnclavePubKey,
            RaveEvidence({
                report: guardian2Rave.report(),
                signature: guardian2Rave.sig(),
                leafX509CertDigest: keccak256(guardian2Rave.signingCert())
            })
        );
        vm.stopPrank();

        vm.startPrank(guardians[2]);
        module.rotateGuardianKey(
            0,
            guardian3EnclavePubKey,
            RaveEvidence({
                report: guardian3Rave.report(),
                signature: guardian3Rave.sig(),
                leafX509CertDigest: keccak256(guardian3Rave.signingCert())
            })
        );
        vm.stopPrank();

        assertEq(module.getGuardiansEnclaveAddress(guardians[0]), guardian1Enclave, "bad enclave address1");
        assertEq(module.getGuardiansEnclaveAddress(guardians[1]), guardian2Enclave, "bad enclave address2");
        assertEq(module.getGuardiansEnclaveAddress(guardians[2]), guardian3Enclave, "bad enclave address3");

        bytes[] memory pubKeys = module.getGuardiansEnclavePubkeys();
        assertEq(pubKeys[0], guardian1EnclavePubKey, "guardian1 pub key");
        assertEq(pubKeys[1], guardian2EnclavePubKey, "guardian2 pub key");
        assertEq(pubKeys[2], guardian3EnclavePubKey, "guardian3 pub key");
    }
}
