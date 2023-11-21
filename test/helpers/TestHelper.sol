// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { PufferDeployment } from "script/DeploymentStructs.sol";
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
        hex"04caf1f9cd82a1284626d405d285250fd6c4f58c469fda05d7fd4f29318aae38e7ccc6f4eaced74d3e2aa3fc0576093860d3045263c4183d694a39911ee9031c73";
    address public guardian2Enclave;
    uint256 public guardian2SKEnclave;
    bytes public guardian2EnclavePubKey =
        hex"04f050c3ce5d575600af388f41876e2962499a97bc8fcfa4a12adf7e4a486a3be9a1db0efd899c09723f83fe490e8215fd596a5f03c819e28a8b95f3cce6238613";
    address public guardian3Enclave;
    uint256 public guardian3SKEnclave;
    bytes public guardian3EnclavePubKey =
        hex"04a55b152177219971a93a64aafc2d61baeaf86526963caa260e71efa2b865527e0307d7bda85312dd6ff23bcc88f2bf228da6295239f72c31b686c48b7b69cdfd";

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
        assumePayable(addr);
        assumeNotPrecompile(addr);
        vm.assume(addr.code.length == 0);
        vm.assume(addr != ADDRESS_ZERO);
        vm.assume(addr != ADDRESS_ONE);
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
        (guardian2, guardian2SK) = makeAddrAndKey("guardian2");
        (guardian3, guardian3SK) = makeAddrAndKey("guardian3");

        // Hardcode enclave secret keys
        guardian1SKEnclave = 81165043675487275545095207072241430673874640255053335052777448899322561824201;
        guardian1Enclave = vm.addr(guardian1SKEnclave);
        guardian2SKEnclave = 90480947395980135991870782913815514305328820213706480966227475230529794843518;
        guardian2Enclave = vm.addr(guardian2SKEnclave);
        guardian3SKEnclave = 56094429399408807348734910221877888701411489680816282162734349635927251229227;
        guardian3Enclave = vm.addr(guardian3SKEnclave);
        guardiansEnclavePks.push(guardian1SKEnclave);
        guardiansEnclavePks.push(guardian2SKEnclave);
        guardiansEnclavePks.push(guardian3SKEnclave);

        address[] memory guardians = new address[](3);
        guardians[0] = guardian1;
        guardians[1] = guardian2;
        guardians[2] = guardian3;

        // Deploy everything with one script
        PufferDeployment memory pufferDeployment = new DeployEverything().run(guardians, 1);

        pufferProtocol = PufferProtocol(pufferDeployment.pufferProtocol);
        accessManager = AccessManager(pufferDeployment.accessManager);
        pool = PufferPool(payable(pufferDeployment.pufferPool));
        withdrawalPool = IWithdrawalPool(pufferDeployment.withdrawalPool);
        verifier = IEnclaveVerifier(pufferDeployment.enclaveVerifier);
        module = GuardianModule(pufferDeployment.guardianModule);
        beacon = UpgradeableBeacon(pufferDeployment.beacon);
        guardiansSafe = Safe(payable(pufferDeployment.guardians));

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

        assertEq(
            blockhash(block.number),
            hex"0000000000000000000000000000000000000000000000000000000000000000",
            "bad blockhash"
        );

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
