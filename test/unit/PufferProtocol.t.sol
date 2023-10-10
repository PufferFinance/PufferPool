// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferProtocolMockUpgrade } from "../mocks/PufferProtocolMockUpgrade.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { TestBase } from "../TestBase.t.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { Status } from "puffer/struct/Status.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { console } from "forge-std/console.sol";

contract PufferProtocolTest is TestHelper, TestBase {
    using ECDSA for bytes32;

    event ValidatorKeyRegistered(bytes indexed pubKey, uint256);
    event SuccesfullyProvisioned(bytes indexed pubKey, uint256);
    event FailedToProvision(bytes indexed pubKey, uint256);
    event ValidatorDequeued(bytes indexed pubKey, uint256 validatorIndex);
    event StrategyWeightsChanged(bytes32[] oldWeights, bytes32[] newWeights);

    bytes zeroPubKey = new bytes(48);
    bytes32 zeroPubKeyPart;

    bytes32 constant NO_RESTAKING = bytes32("NO_RESTAKING");
    bytes32 constant EIGEN_DA = bytes32("EIGEN_DA");
    bytes32 constant CRAZY_GAINS = bytes32("CRAZY_GAINS");

    function setUp() public override {
        super.setUp();

        vm.deal(address(this), 1000 ether);

        // Setup roles
        bytes4[] memory selectors = new bytes4[](6);
        selectors[0] = PufferProtocol.setProtocolFeeRate.selector;
        selectors[1] = PufferProtocol.setSmoothingCommitment.selector;
        selectors[2] = PufferProtocol.createPufferStrategy.selector;
        selectors[3] = PufferProtocol.setStrategyWeights.selector;
        selectors[4] = PufferProtocol.setValidatorLimitPerInterval.selector;
        selectors[5] = bytes4(hex"4f1ef286"); // signature for UUPS.upgradeToAndCall(address newImplementation, bytes memory data)

        // For simplicity transfer ownership to this contract
        vm.startPrank(_broadcaster);
        accessManager.setTargetFunctionRole(address(pufferProtocol), selectors, ROLE_ID_DAO);
        accessManager.grantRole(ROLE_ID_DAO, address(this), 0);
        vm.stopPrank();

        pufferProtocol.setSmoothingCommitment(NO_RESTAKING, 1.5 ether);

        _skipDefaultFuzzAddresses();

        fuzzedAddressMapping[address(pufferProtocol)] = true;
    }

    // Setup
    function testSetup() public {
        assertTrue(pufferProtocol.getWithdrawalPool() != address(0), "non zero address");
    }

    // Test Skipping the validator
    function testSkipProvisioning() public {
        vm.deal(address(pool), 1000 ether);

        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("bob"), NO_RESTAKING);

        (bytes32 strategyName, uint256 idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(strategyName, NO_RESTAKING, "strategy");
        assertEq(idx, 0, "idx");

        vm.prank(address(guardiansSafe));
        pufferProtocol.skipProvisioning(NO_RESTAKING);

        Validator memory aliceValidator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 0);
        assertTrue(aliceValidator.status == Status.SKIPPED, "did not update status");

        (strategyName, idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(strategyName, NO_RESTAKING, "strategy");
        assertEq(idx, 1, "idx should be 1");

        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("bob")), 1);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(_getPubKey(bytes32("bob")))
        });
    }

    // Create an existing strategy should revert
    function testCreateExistingStrategyShouldFail() public {
        vm.expectRevert(IPufferProtocol.Create2Failed.selector);
        pufferProtocol.createPufferStrategy(NO_RESTAKING);
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

    // Try registering with invalid strategy
    function testRegisterToInvalidStrategy() public {
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(bytes32("imaginary strategy"));
        bytes memory pubKey = _getPubKey(bytes32("charlie"));
        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey);
        vm.expectRevert(IPufferProtocol.InvalidPufferStrategy.selector);
        pufferProtocol.registerValidatorKey{ value: smoothingCommitment }(
            validatorKeyData, bytes32("imaginary strategy")
        );
    }

    // Try registering with invalid amount paid
    function testRegisterWithInvalidAmountPaid() public {
        bytes memory pubKey = _getPubKey(bytes32("charlie"));
        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey);
        vm.expectRevert(IPufferProtocol.InvalidETHAmount.selector);
        pufferProtocol.registerValidatorKey{ value: 5 ether }(validatorKeyData, NO_RESTAKING);
    }

    // Test extending validator commitment
    function testExtendCommitment() public {
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        Validator memory validator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 0);
        assertTrue(validator.node == address(this), "node operator");

        uint256 firstPayment = validator.lastCommitmentPayment;
        assertEq(firstPayment, block.timestamp, "lastPayment");

        vm.warp(1000);

        vm.expectRevert(IPufferProtocol.InvalidETHAmount.selector);
        pufferProtocol.extendCommitment{ value: 0 }(NO_RESTAKING, 0);

        pufferProtocol.extendCommitment{ value: pufferProtocol.getSmoothingCommitment(NO_RESTAKING) }(NO_RESTAKING, 0);

        validator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 0);

        assertTrue(validator.lastCommitmentPayment == block.timestamp, "lastPayment");
    }

    // Try updating for future block
    function testProofOfReserve() external {
        vm.startPrank(address(guardiansSafe));

        vm.expectRevert(IPufferProtocol.InvalidData.selector);
        pufferProtocol.proofOfReserve({ ethAmount: 2 ether, lockedETH: 0, pufETHTotalSupply: 1 ether, blockNumber: 2 });

        vm.roll(50401);

        pufferProtocol.proofOfReserve({
            ethAmount: 2 ether,
            lockedETH: 32 ether,
            pufETHTotalSupply: 1 ether,
            blockNumber: 50401
        });

        // Second update should revert as it has not passed enough time between two updates
        vm.expectRevert(IPufferProtocol.InvalidData.selector);
        pufferProtocol.proofOfReserve({
            ethAmount: 2 ether,
            lockedETH: 0,
            pufETHTotalSupply: 1 ether,
            blockNumber: 50401
        });
    }

    // Change smoothing commitment for default strategy
    function testSetSmoothingCommitment() external {
        uint256 commitmentBefore = pufferProtocol.getSmoothingCommitment(NO_RESTAKING);
        pufferProtocol.setSmoothingCommitment(NO_RESTAKING, 20 ether);
        uint256 commitmentAfter = pufferProtocol.getSmoothingCommitment(NO_RESTAKING);
        assertEq(commitmentAfter, 20 ether, "after");
        assertTrue(commitmentBefore != commitmentAfter, "should change");
    }

    // Change smoothing non existent strategy
    function testSetSmoothingCommitment(bytes32 strategy) external {
        uint256 commitmentBefore = pufferProtocol.getSmoothingCommitment(strategy);
        pufferProtocol.setSmoothingCommitment(strategy, 20 ether);
        uint256 commitmentAfter = pufferProtocol.getSmoothingCommitment(strategy);
        assertEq(commitmentAfter, 20 ether, "after");
        assertTrue(commitmentBefore != commitmentAfter, "should change");
    }

    // Try registering without RAVE evidence
    function testRegisterWithoutRAVE() public {
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(NO_RESTAKING);

        bytes memory pubKey = _getPubKey(bytes32("something"));

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
            raveEvidence: new bytes(0) // No rave
         });

        vm.expectRevert(IPufferProtocol.InvalidRaveEvidence.selector);
        pufferProtocol.registerValidatorKey{ value: smoothingCommitment }(validatorData, NO_RESTAKING);
    }

    // Try registering more validators than the allowed number
    function testRegisterMoreValidatorsThanTheLimit() public {
        uint256 previousInterval = pufferProtocol.getValidatorLimitPerInterval();
        assertEq(previousInterval, 20, "previous limit");
        pufferProtocol.setValidatorLimitPerInterval(2);
        uint256 newInterval = pufferProtocol.getValidatorLimitPerInterval();
        assertEq(newInterval, 2, "new limit");

        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("bob"), NO_RESTAKING);

        // Third one should revert
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(NO_RESTAKING);
        bytes memory pubKey = _getPubKey(bytes32("charlie"));
        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey);
        vm.expectRevert(IPufferProtocol.ValidatorLimitPerIntervalReached.selector);
        pufferProtocol.registerValidatorKey{ value: smoothingCommitment }(validatorKeyData, NO_RESTAKING);
    }

    function testSetProtocolFeeRate() public {
        uint256 rate = 20 * FixedPointMathLib.WAD;
        pufferProtocol.setProtocolFeeRate(rate); // 20%
        assertEq(pufferProtocol.getProtocolFeeRate(), rate, "new rate");
    }

    function _registerValidatorKey(bytes32 pubKeyPart, bytes32 strategyName) internal {
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(strategyName);

        bytes memory pubKey = _getPubKey(pubKeyPart);

        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey);

        uint256 idx = pufferProtocol.getPendingValidatorIndex(strategyName);

        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, idx);
        pufferProtocol.registerValidatorKey{ value: smoothingCommitment }(validatorKeyData, strategyName);
    }

    function testStopRegistration() public {
        _registerValidatorKey(zeroPubKeyPart, NO_RESTAKING);

        vm.prank(address(4123123)); // random sender
        vm.expectRevert(IPufferProtocol.Unauthorized.selector);
        pufferProtocol.stopRegistration(NO_RESTAKING, 0);

        vm.expectEmit(true, true, true, true);
        emit ValidatorDequeued(zeroPubKey, 0);
        pufferProtocol.stopRegistration(NO_RESTAKING, 0);

        vm.expectEmit(true, true, true, true);
        emit FailedToProvision(zeroPubKey, 0);
        vm.startPrank(address(guardiansSafe));
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });
        vm.stopPrank();

        // Invalid status
        vm.expectRevert(IPufferProtocol.InvalidValidatorState.selector);
        pufferProtocol.stopRegistration(NO_RESTAKING, 0);
    }

    function testRegisterMultipleValidatorKeysAndDequeue(bytes32 alicePubKeyPart, bytes32 bobPubKeyPart) public {
        address bob = makeAddr("bob");
        vm.deal(bob, 10 ether);
        address alice = makeAddr("alice");
        vm.deal(alice, 10 ether);

        bytes memory bobPubKey = _getPubKey(bobPubKeyPart);
        bytes memory alicePubKey = _getPubKey(alicePubKeyPart);

        // 1. validator
        _registerValidatorKey(zeroPubKeyPart, NO_RESTAKING);

        Validator memory validator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 0);
        assertTrue(validator.node == address(this), "node operator");
        assertTrue(keccak256(validator.pubKey) == keccak256(zeroPubKey), "bad pubkey");

        // 2. validator
        vm.startPrank(bob);
        _registerValidatorKey(bobPubKeyPart, NO_RESTAKING);
        vm.stopPrank();

        // 3. validator
        vm.startPrank(alice);
        _registerValidatorKey(alicePubKeyPart, NO_RESTAKING);
        vm.stopPrank();

        // 4. validator
        _registerValidatorKey(zeroPubKeyPart, NO_RESTAKING);

        // 5. Validator
        _registerValidatorKey(zeroPubKeyPart, NO_RESTAKING);

        assertEq(pufferProtocol.getPendingValidatorIndex(NO_RESTAKING), 5, "next pending validator index");
        assertEq(pufferProtocol.getValidators(NO_RESTAKING).length, 5, "5 registered validators");
        assertEq(pufferProtocol.getValidatorsAddresses(NO_RESTAKING).length, 5, "5 registered node operators");

        vm.deal(address(pool), 1000 ether);

        vm.startPrank(address(guardiansSafe));
        // // 1. provision zero key
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(zeroPubKey, 0);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });

        // Provision Bob that is not zero pubKey
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(bobPubKey, 1);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(bobPubKey)
        });

        Validator memory bobValidator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 1);

        assertTrue(bobValidator.status == Status.ACTIVE, "bob should be active");

        // Submit invalid TX by guardians, bad signature
        // It should dequeue alice
        vm.expectEmit(true, true, true, true);
        emit FailedToProvision(alicePubKey, 2);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(55),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });

        emit SuccesfullyProvisioned(zeroPubKey, 3);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });
    }

    function testCreatePufferStrategy() public {
        pufferProtocol.createPufferStrategy(bytes32("LEVERAGED_RESTAKING"));
    }

    function testSetStrategyWeights() public {
        pufferProtocol.createPufferStrategy(EIGEN_DA);
        pufferProtocol.createPufferStrategy(CRAZY_GAINS);

        bytes32[] memory oldWeights = new bytes32[](1);
        oldWeights[0] = NO_RESTAKING;

        bytes32[] memory newWeights = new bytes32[](4);
        newWeights[0] = NO_RESTAKING;
        newWeights[1] = EIGEN_DA;
        newWeights[2] = EIGEN_DA;
        newWeights[3] = CRAZY_GAINS;

        vm.expectEmit(true, true, true, true);
        emit StrategyWeightsChanged(oldWeights, newWeights);
        pufferProtocol.setStrategyWeights(newWeights);

        vm.deal(address(pool), 10000 ether);

        _registerValidatorKey(bytes32("bob"), NO_RESTAKING);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("charlie"), NO_RESTAKING);
        _registerValidatorKey(bytes32("david"), NO_RESTAKING);
        _registerValidatorKey(bytes32("emma"), NO_RESTAKING);
        _registerValidatorKey(bytes32("benjamin"), EIGEN_DA);
        _registerValidatorKey(bytes32("rocky"), CRAZY_GAINS);

        (bytes32 nextStrategy, uint256 nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextStrategy == NO_RESTAKING, "strategy selection");
        assertTrue(nextId == 0, "strategy selection");

        // Provision Bob that is not zero pubKey
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("bob")), 0);
        vm.startPrank(address(guardiansSafe));
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(_getPubKey(bytes32("bob")))
        });

        (nextStrategy, nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextStrategy == EIGEN_DA, "strategy selection");
        // Id is zero, because that is the first in this queue
        assertTrue(nextId == 0, "strategy id");

        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("benjamin")), 0);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(_getPubKey(bytes32("benjamin")))
        });

        (nextStrategy, nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextStrategy == EIGEN_DA, "strategy selection");
        assertTrue(nextId == 1, "strategy id");

        vm.expectEmit(true, true, true, true);
        emit FailedToProvision("", 1);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(zeroPubKey)
        });

        (nextStrategy, nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextStrategy == CRAZY_GAINS, "strategy selection");
        assertTrue(nextId == 0, "strategy id");

        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("rocky")), 0);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(_getPubKey(bytes32("rocky")))
        });

        (nextStrategy, nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextStrategy == NO_RESTAKING, "strategy selection");
        assertTrue(nextId == 1, "strategy id");

        assertEq(
            pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING), 1, "next idx for no restaking strategy"
        );

        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("alice")), 1);
        pufferProtocol.provisionNodeETHWrapper({
            signature: new bytes(0),
            depositDataRoot: "",
            guardianEnclaveSignatures: _getGuardianSignatures(_getPubKey(bytes32("alice")))
        });
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
        (bytes32 strategyName, uint256 pendingIdx) = pufferProtocol.getNextValidatorToProvision();
        Validator memory validator = pufferProtocol.getValidatorInfo(strategyName, pendingIdx);
        // If there is no strategy return empty byte array
        if (validator.strategy == address(0)) {
            return new bytes[](0);
        }
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
            raveEvidence: new bytes(1) // Guardians are checking it off chain
         });

        return validatorData;
    }

    function _getPubKey(bytes32 pubKeypart) internal pure returns (bytes memory) {
        return bytes.concat(abi.encodePacked(pubKeypart), bytes16(""));
    }
}
