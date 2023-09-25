// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferServiceManagerMockUpgrade } from "./mocks/PufferServiceManagerMockUpgrade.sol";
import { TestHelper } from "./helpers/TestHelper.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { TestBase } from "./TestBase.t.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { IPufferServiceManager } from "puffer/interface/IPufferServiceManager.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { BeaconMock } from "./mocks/BeaconMock.sol";
import { Status } from "puffer/struct/Status.sol";
import { Validator } from "puffer/struct/Validator.sol";

contract PufferServiceManagerTest is TestHelper, TestBase {
    using ECDSA for bytes32;

    event ValidatorKeyRegistered(bytes, uint256);
    event SuccesfullyProvisioned(bytes, uint256);
    event FailedToProvision(bytes, uint256);
    event ValidatorDequeued(bytes pubKey, uint256 validatorIndex);

    bytes zeroPubKey = new bytes(48);

    function setUp() public override {
        super.setUp();

        // For simplicity transfer ownership to this contract
        vm.prank(_broadcaster);
        serviceManager.transferOwnership(address(this));

        _skipDefaultFuzzAddresses();

        BeaconMock mock = new BeaconMock();
        vm.etch(address(pool.BEACON_DEPOSIT_CONTRACT()), address(mock).code);

        fuzzedAddressMapping[address(serviceManager)] = true;
    }

    function testRegisterInvalidValidatorKeyShouldRevert(bytes memory pubKey) public {
        vm.assume(pubKey.length != 48);
        vm.expectRevert(IPufferServiceManager.InvalidBLSPubKey.selector);
        serviceManager.registerValidatorKey(_getMockValidatorKeyData(pubKey));
    }

    function testRegisterInvalidPubKeyShares() public {
        ValidatorKeyData memory data = _getMockValidatorKeyData(new bytes(48));
        data.blsPubKeyShares = new bytes[](2);

        vm.expectRevert(IPufferServiceManager.InvalidBLSPublicKeyShares.selector);
        serviceManager.registerValidatorKey(data);
    }

    function testRegisterInvalidPrivKeyShares() public {
        ValidatorKeyData memory data = _getMockValidatorKeyData(new bytes(48));
        data.blsEncryptedPrivKeyShares = new bytes[](2);

        vm.expectRevert(IPufferServiceManager.InvalidBLSPrivateKeyShares.selector);
        serviceManager.registerValidatorKey(data);
    }

    function testGetConsensusCommission() public {
        uint256 comission = 10 * FixedPointMathLib.WAD;

        assertEq(serviceManager.getConsensusCommission(), 0, "zero comission");
        serviceManager.setConsensusCommission(comission);
        assertEq(serviceManager.getConsensusCommission(), comission, "non zero comission");
    }

    function testSetProtocolFeeRate() public {
        uint256 rate = 20 * FixedPointMathLib.WAD;
        serviceManager.setProtocolFeeRate(rate); // 20%
        assertEq(serviceManager.getProtocolFeeRate(), rate, "new rate");
    }

    function testRegisterValidatorKey(bytes memory pubKey) public {
        vm.assume(pubKey.length == 48);
        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, serviceManager.getPendingValidatorIndex());
        serviceManager.registerValidatorKey(_getMockValidatorKeyData(pubKey));
    }

    function testStopRegistration() public {
        testRegisterValidatorKey(zeroPubKey);

        vm.prank(address(4123123)); // random sender
        vm.expectRevert(IPufferServiceManager.Unauthorized.selector);
        serviceManager.stopRegistration(0);

        // Stop registration for 4.
        vm.expectEmit(true, true, true, true);
        emit ValidatorDequeued(zeroPubKey, 0);
        serviceManager.stopRegistration(0);

        vm.expectEmit(true, true, true, true);
        emit FailedToProvision(zeroPubKey, 0);
        serviceManager.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });

        // Invalid status
        vm.expectRevert(IPufferServiceManager.InvalidValidatorState.selector);
        serviceManager.stopRegistration(0);
    }

    function testRegisterMultipleValidatorKeysAndDequeue() public {
        address bob = makeAddr("bob");
        address alice = makeAddr("alice");

        bytes memory bobPubKey =
            hex"99131eddc46538c04d75a3c9c8d52ea22d089c7f28b7d24b973eb40148eb07174dbcfecf2b4ebdee14044778300a1dba";
        bytes memory alicePubKey =
            hex"8ff11ee87341660e4915dd060564d43b68c1d27ea5c2dca423d246641f3eacd781a000470ba3d2ea333d82c4a8eb0cc2";

        // 1. validator
        testRegisterValidatorKey(zeroPubKey);

        // 2. validator
        vm.startPrank(bob);
        testRegisterValidatorKey(bobPubKey);
        vm.stopPrank();

        // 3. validator
        vm.startPrank(alice);
        testRegisterValidatorKey(alicePubKey);
        vm.stopPrank();

        // 4. validator
        testRegisterValidatorKey(zeroPubKey);

        // 5. Validator
        testRegisterValidatorKey(zeroPubKey);

        assertEq(serviceManager.getPendingValidatorIndex(), 5, "next pending validator index");

        assertEq(serviceManager.getValidators().length, 0, "no validators");
        assertEq(serviceManager.getValidatorsAddresses().length, 0, "no validators");

        vm.deal(address(pool), 1000 ether);

        // 1. provision zero key
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(new bytes(48), 0);
        serviceManager.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });

        assertEq(serviceManager.getValidators().length, 1, "1 validator");
        assertEq(serviceManager.getValidatorsAddresses().length, 1, "1 validator");

        // Provision Bob that is not zero pubKey
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(bobPubKey, 1);
        serviceManager.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(bobPubKey)
        });

        Validator memory bobValidator = serviceManager.getValidatorInfo(1);

        assertTrue(bobValidator.status == Status.ACTIVE, "bob should be active");

        assertEq(serviceManager.getValidators().length, 2, "2 validators");
        assertEq(serviceManager.getValidatorsAddresses().length, 2, "2 validators");
        assertEq(serviceManager.getValidatorsAddresses()[1], bob, "bob should be second validator");

        // Submit invalid TX by guardians, bad signature
        // It should dequeue alice
        vm.expectEmit(true, true, true, true);
        emit FailedToProvision(alicePubKey, 2);
        serviceManager.provisionNodeETHWrapper({
            signature: new bytes(55),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });

        emit SuccesfullyProvisioned(new bytes(48), 3);
        serviceManager.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });

        assertEq(serviceManager.getValidators().length, 4, "4 validators");
        assertEq(serviceManager.getValidatorsAddresses().length, 4, "4 validators provisioned");
    }

    function _getGuardianSignatures(bytes memory pubKey) internal view returns (bytes[] memory) {
        bytes32 digest =
            (serviceManager.getGuardianModule()).getMessageToBeSigned(serviceManager, pubKey, new bytes(0), bytes32(""));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardian1SKEnclave, digest);
        bytes memory signature1 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        (v, r, s) = vm.sign(guardian2SKEnclave, digest);
        (v, r, s) = vm.sign(guardian3SKEnclave, digest);
        bytes memory signature2 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        (v, r, s) = vm.sign(guardian3SKEnclave, digest);
        bytes memory signature3 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        bytes[] memory guardianSignatures = new bytes[](3);
        guardianSignatures[0] = signature1;
        guardianSignatures[1] = signature2;
        guardianSignatures[2] = signature3;

        return guardianSignatures;
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

    function _getMockValidatorKeyData(bytes memory pubKey) internal pure returns (ValidatorKeyData memory) {
        bytes[] memory newSetOfPubKeys = new bytes[](3);

        // we have 3 guardians in TestHelper.sol
        newSetOfPubKeys[0] = bytes("key1");
        newSetOfPubKeys[0] = bytes("key2");
        newSetOfPubKeys[0] = bytes("key3");

        ValidatorKeyData memory validatorData = ValidatorKeyData({
            blsPubKey: pubKey, // key length must be 48 byte
            signature: new bytes(0),
            depositDataRoot: bytes32(""),
            blsEncryptedPrivKeyShares: new bytes[](3),
            blsPubKeyShares: new bytes[](3),
            blockNumber: 1,
            raveEvidence: new bytes(0)
        });

        return validatorData;
    }
}
