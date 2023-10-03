// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferProtocolMockUpgrade } from "../mocks/PufferProtocolMockUpgrade.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { TestBase } from "../TestBase.t.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { BeaconMock } from "../mocks/BeaconMock.sol";
import { Status } from "puffer/struct/Status.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";

contract PufferProtocolTest is TestHelper, TestBase {
    using ECDSA for bytes32;

    event ValidatorKeyRegistered(bytes, uint256);
    event SuccesfullyProvisioned(bytes, uint256);
    event FailedToProvision(bytes, uint256);
    event ValidatorDequeued(bytes pubKey, uint256 validatorIndex);

    bytes zeroPubKey = new bytes(48);
    bytes32 zeroPubKeyPart;

    bytes32 constant NO_RESTAKING = bytes32("NO_RESTAKING");
    uint256 executionRewardsCommitment = 0.5 ether;
    uint256 consensusRewardsCommitment = 1 ether;

    function setUp() public override {
        super.setUp();

        vm.deal(address(this), 1000 ether);

        // Setup roles
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = PufferProtocol.setProtocolFeeRate.selector;
        selectors[1] = PufferProtocol.setCommitment.selector;
        selectors[2] = PufferProtocol.createPufferStrategy.selector;
        selectors[3] = bytes4(hex"4f1ef286"); // signature for UUPS.upgradeToAndCall(address newImplementation, bytes memory data)

        // For simplicity transfer ownership to this contract
        vm.startPrank(_broadcaster);
        accessManager.setTargetFunctionRole(address(pufferProtocol), selectors, ROLE_ID_DAO);
        accessManager.grantRole(ROLE_ID_DAO, address(this), 0);
        vm.stopPrank();

        pufferProtocol.setCommitment(executionRewardsCommitment + consensusRewardsCommitment);

        _skipDefaultFuzzAddresses();

        BeaconMock mock = new BeaconMock();
        vm.etch(address(pool.BEACON_DEPOSIT_CONTRACT()), address(mock).code);

        fuzzedAddressMapping[address(pufferProtocol)] = true;
    }

    // Invalid BLS pub key length
    function testRegisterInvalidValidatorKeyShouldRevert() public {
        vm.expectRevert(IPufferProtocol.InvalidBLSPubKey.selector);
        pufferProtocol.registerValidatorKey{ value: 4 ether }(_getMockValidatorKeyData(new bytes(33)), NO_RESTAKING);
    }

    // Invalid pub key shares length
    function testRegisterInvalidPubKeyShares() public {
        ValidatorKeyData memory data = _getMockValidatorKeyData(new bytes(48));
        data.blsPubKeyShares = new bytes[](2);

        vm.expectRevert(IPufferProtocol.InvalidBLSPublicKeyShares.selector);
        pufferProtocol.registerValidatorKey{ value: 4 ether }(data, NO_RESTAKING);
    }

    // Invalid private key shares length
    function testRegisterInvalidPrivKeyShares() public {
        ValidatorKeyData memory data = _getMockValidatorKeyData(new bytes(48));
        data.blsEncryptedPrivKeyShares = new bytes[](2);

        vm.expectRevert(IPufferProtocol.InvalidBLSPrivateKeyShares.selector);
        pufferProtocol.registerValidatorKey{ value: 4 ether }(data, NO_RESTAKING);
    }

    function testSetProtocolFeeRate() public {
        uint256 rate = 20 * FixedPointMathLib.WAD;
        pufferProtocol.setProtocolFeeRate(rate); // 20%
        assertEq(pufferProtocol.getProtocolFeeRate(), rate, "new rate");
    }

    function testRegisterValidatorKey(bytes32 pubKeyPart) public {
        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(_getPubKey(pubKeyPart), pufferProtocol.getPendingValidatorIndex());
        pufferProtocol.registerValidatorKey{ value: consensusRewardsCommitment + executionRewardsCommitment }(
            _getMockValidatorKeyData(_getPubKey(pubKeyPart)), NO_RESTAKING
        );
    }

    function testStopRegistration() public {
        testRegisterValidatorKey(zeroPubKeyPart);

        vm.prank(address(4123123)); // random sender
        vm.expectRevert(IPufferProtocol.Unauthorized.selector);
        pufferProtocol.stopRegistration(0);

        // Stop registration for 4.
        vm.expectEmit(true, true, true, true);
        emit ValidatorDequeued(zeroPubKey, 0);
        pufferProtocol.stopRegistration(0);

        vm.expectEmit(true, true, true, true);
        emit FailedToProvision(zeroPubKey, 0);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });

        // Invalid status
        vm.expectRevert(IPufferProtocol.InvalidValidatorState.selector);
        pufferProtocol.stopRegistration(0);
    }

    function testRegisterMultipleValidatorKeysAndDequeue(bytes32 alicePubKeyPart, bytes32 bobPubKeyPart) public {
        address bob = makeAddr("bob");
        vm.deal(bob, 10 ether);
        address alice = makeAddr("alice");
        vm.deal(alice, 10 ether);

        bytes memory bobPubKey = _getPubKey(bobPubKeyPart);
        bytes memory alicePubKey = _getPubKey(alicePubKeyPart);

        // 1. validator
        testRegisterValidatorKey(zeroPubKeyPart);

        // 2. validator
        vm.startPrank(bob);
        testRegisterValidatorKey(bobPubKeyPart);
        vm.stopPrank();

        // 3. validator
        vm.startPrank(alice);
        testRegisterValidatorKey(alicePubKeyPart);
        vm.stopPrank();

        // 4. validator
        testRegisterValidatorKey(zeroPubKeyPart);

        // 5. Validator
        testRegisterValidatorKey(zeroPubKeyPart);

        assertEq(pufferProtocol.getPendingValidatorIndex(), 5, "next pending validator index");

        assertEq(pufferProtocol.getValidators().length, 0, "no validators");
        assertEq(pufferProtocol.getValidatorsAddresses().length, 0, "no validators");

        vm.deal(address(pool), 1000 ether);

        // 1. provision zero key
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(new bytes(48), 0);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });

        assertEq(pufferProtocol.getValidators().length, 1, "1 validator");
        assertEq(pufferProtocol.getValidatorsAddresses().length, 1, "1 validator");

        // Provision Bob that is not zero pubKey
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(bobPubKey, 1);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(bobPubKey)
        });

        Validator memory bobValidator = pufferProtocol.getValidatorInfo(1);

        assertTrue(bobValidator.status == Status.ACTIVE, "bob should be active");

        assertEq(pufferProtocol.getValidators().length, 2, "2 validators");
        assertEq(pufferProtocol.getValidatorsAddresses().length, 2, "2 validators");
        assertEq(pufferProtocol.getValidatorsAddresses()[1], bob, "bob should be second validator");

        // Submit invalid TX by guardians, bad signature
        // It should dequeue alice
        vm.expectEmit(true, true, true, true);
        emit FailedToProvision(alicePubKey, 2);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(55),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });

        emit SuccesfullyProvisioned(new bytes(48), 3);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });

        assertEq(pufferProtocol.getValidators().length, 4, "4 validators");
        assertEq(pufferProtocol.getValidatorsAddresses().length, 4, "4 validators provisioned");
    }

    function testCreatePufferStrategy() public {
        pufferProtocol.createPufferStrategy(bytes32("LEVERAGED_RESTAKING"));
    }

    // Test smart contract upgradeability (UUPS)
    function testUpgrade() public {
        vm.expectRevert();
        uint256 result = PufferProtocolMockUpgrade(payable(address(pool))).returnSomething();

        PufferProtocolMockUpgrade newImplementation = new PufferProtocolMockUpgrade(address(beacon));
        pufferProtocol.upgradeToAndCall(address(newImplementation), "");

        result = PufferProtocolMockUpgrade(payable(address(pufferProtocol))).returnSomething();

        assertEq(result, 1337);
    }

    function _getGuardianSignatures(bytes memory pubKey) internal view returns (bytes[] memory) {
        uint256 pendindIdx = pufferProtocol.getPendingValidatorIndex();
        Validator memory validator = pufferProtocol.getValidatorInfo(pendindIdx - 1); // -1 because we are in the middle of provisioning
        bytes memory withdrawalCredentials = pufferProtocol.getWithdrawalCredentials(validator.strategy);

        bytes32 digest = (pufferProtocol.getGuardianModule()).getMessageToBeSigned(
            pubKey, new bytes(0), withdrawalCredentials, bytes32("")
        );

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

    function _getPubKey(bytes32 pubKeypart) internal pure returns (bytes memory) {
        return bytes.concat(abi.encodePacked(pubKeypart), bytes16(""));
    }
}
