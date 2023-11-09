// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferProtocolMockUpgrade } from "../mocks/PufferProtocolMockUpgrade.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { Status } from "puffer/struct/Status.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferStrategy } from "puffer/PufferStrategy.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";
import { ROLE_ID_DAO, ROLE_ID_PUFFER_PROTOCOL } from "script/SetupAccess.s.sol";
import { Unauthorized } from "puffer/Errors.sol";

contract PufferProtocolTest is TestHelper {
    using ECDSA for bytes32;

    event ValidatorKeyRegistered(bytes indexed pubKey, uint256 indexed, bytes32 indexed, bool);
    event SuccesfullyProvisioned(bytes indexed pubKey, uint256 indexed, bytes32 indexed);
    event FailedToProvision(bytes indexed pubKey, uint256);
    event ValidatorDequeued(bytes indexed pubKey, uint256 validatorIndex);
    event StrategyWeightsChanged(bytes32[] oldWeights, bytes32[] newWeights);

    bytes zeroPubKey = new bytes(48);
    bytes32 zeroPubKeyPart;

    bytes32 constant EIGEN_DA = bytes32("EIGEN_DA");
    bytes32 constant CRAZY_GAINS = bytes32("CRAZY_GAINS");

    function setUp() public override {
        super.setUp();

        vm.deal(address(this), 1000 ether);

        // Setup roles
        bytes4[] memory selectors = new bytes4[](6);
        selectors[0] = PufferProtocol.setProtocolFeeRate.selector;
        selectors[1] = PufferProtocol.setSmoothingCommitments.selector;
        selectors[2] = PufferProtocol.createPufferStrategy.selector;
        selectors[3] = PufferProtocol.setStrategyWeights.selector;
        selectors[4] = PufferProtocol.setValidatorLimitPerInterval.selector;
        selectors[5] = bytes4(hex"4f1ef286"); // signature for UUPS.upgradeToAndCall(address newImplementation, bytes memory data)

        // For simplicity grant DAO role to this contract
        vm.startPrank(_broadcaster);
        accessManager.setTargetFunctionRole(address(pufferProtocol), selectors, ROLE_ID_DAO);
        accessManager.grantRole(ROLE_ID_DAO, address(this), 0);
        vm.stopPrank();

        _skipDefaultFuzzAddresses();

        fuzzedAddressMapping[address(pufferProtocol)] = true;
    }

    // Setup
    function testSetup() public {
        assertTrue(address(pufferProtocol.getWithdrawalPool()) != address(0), "non zero address");
        address strategy = pufferProtocol.getStrategyAddress(NO_RESTAKING);
        assertEq(PufferStrategy(payable(strategy)).NAME(), NO_RESTAKING, "bad name");
    }

    function testEmptyQueue() public {
        (bytes32 strategyName, uint256 idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(strategyName, bytes32("NO_VALIDATORS"), "name");
        assertEq(idx, type(uint256).max, "name");
    }

    // Test Skipping the validator
    function testSkipProvisioning() public {
        vm.deal(address(pool), 1000 ether);

        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("bob"), NO_RESTAKING);

        (bytes32 strategyName, uint256 idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(strategyName, NO_RESTAKING, "strategy");
        assertEq(idx, 0, "idx");

        assertTrue(pool.balanceOf(address(this)) == 0, "zero pufETH");

        vm.prank(address(guardiansSafe));
        pufferProtocol.skipProvisioning(NO_RESTAKING);

        // This contract shluld receive pufETH because of the skipProvisioning
        assertTrue(pool.balanceOf(address(this)) != 0, "non zero pufETH");

        Validator memory aliceValidator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 0);
        assertTrue(aliceValidator.status == Status.SKIPPED, "did not update status");

        (strategyName, idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(strategyName, NO_RESTAKING, "strategy");
        assertEq(idx, 1, "idx should be 1");

        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("bob")), 1, NO_RESTAKING);
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("bob"))));
    }

    // Create an existing strategy should revert
    function testCreateExistingStrategyShouldFail() public {
        vm.startPrank(DAO);
        vm.expectRevert(IPufferProtocol.StrategyAlreadyExists.selector);
        pufferProtocol.createPufferStrategy(NO_RESTAKING);
    }

    // Invalid pub key shares length
    function testRegisterInvalidPubKeyShares() public {
        ValidatorKeyData memory data = _getMockValidatorKeyData(new bytes(48), NO_RESTAKING);
        data.blsPubKeySet = new bytes(22);

        vm.expectRevert(IPufferProtocol.InvalidBLSPublicKeySet.selector);
        pufferProtocol.registerValidatorKey{ value: 4 ether }(data, NO_RESTAKING, 1);
    }

    // Invalid private key shares length
    function testRegisterInvalidPrivKeyShares() public {
        ValidatorKeyData memory data = _getMockValidatorKeyData(new bytes(48), NO_RESTAKING);
        data.blsEncryptedPrivKeyShares = new bytes[](2);

        vm.expectRevert(IPufferProtocol.InvalidBLSPrivateKeyShares.selector);
        pufferProtocol.registerValidatorKey{ value: 4 ether }(data, NO_RESTAKING, 1);
    }

    // Try registering with invalid strategy
    function testRegisterToInvalidStrategy() public {
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(1);
        bytes memory pubKey = _getPubKey(bytes32("charlie"));
        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        vm.expectRevert(IPufferProtocol.InvalidPufferStrategy.selector);
        pufferProtocol.registerValidatorKey{ value: smoothingCommitment }(
            validatorKeyData, bytes32("imaginary strategy"), 1
        );
    }

    // Try registering with invalid amount paid
    function testRegisterWithInvalidAmountPaid() public {
        bytes memory pubKey = _getPubKey(bytes32("charlie"));
        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        vm.expectRevert(IPufferProtocol.InvalidETHAmount.selector);
        pufferProtocol.registerValidatorKey{ value: 5 ether }(validatorKeyData, NO_RESTAKING, 1);
    }

    function testStrategyDOS() external {
        vm.deal(address(pool), 1000 ether);

        bytes32[] memory weights = pufferProtocol.getStrategyWeights();
        assertEq(weights.length, 1, "only one strategy");
        assertEq(weights[0], NO_RESTAKING, "no restaking");

        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("bob"), NO_RESTAKING);
        _registerValidatorKey(bytes32("charlie"), NO_RESTAKING);
        _registerValidatorKey(bytes32("dave"), NO_RESTAKING);
        _registerValidatorKey(bytes32("emma"), NO_RESTAKING);
        _registerValidatorKey(bytes32("ford"), NO_RESTAKING);
        _registerValidatorKey(bytes32("greg"), NO_RESTAKING);
        _registerValidatorKey(bytes32("hannah"), NO_RESTAKING);
        _registerValidatorKey(bytes32("ian"), NO_RESTAKING);
        _registerValidatorKey(bytes32("joan"), NO_RESTAKING);
        _registerValidatorKey(bytes32("kim"), NO_RESTAKING);

        // If we stop registration for 0, it will advance the counter
        // Simulate that somebody registered more validators
        // pufferProtocol.stopRegistration(NO_RESTAKING, 0);
        pufferProtocol.stopRegistration(NO_RESTAKING, 1);
        pufferProtocol.stopRegistration(NO_RESTAKING, 2);
        pufferProtocol.stopRegistration(NO_RESTAKING, 3);
        pufferProtocol.stopRegistration(NO_RESTAKING, 4);
        // Skip 5, we want to provision 5
        pufferProtocol.stopRegistration(NO_RESTAKING, 6);
        pufferProtocol.stopRegistration(NO_RESTAKING, 7);

        (bytes32 strategy, uint256 idx) = pufferProtocol.getNextValidatorToProvision();
        assertEq(strategy, NO_RESTAKING, "strategy");
        assertEq(idx, 0, "idx");

        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))));

        uint256 next = pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING);
        assertEq(next, 1, "next idx");

        (strategy, idx) = pufferProtocol.getNextValidatorToProvision();
        assertEq(strategy, NO_RESTAKING, "strategy");
        assertEq(idx, 5, "idx");

        // Provision node updates the idx to current + 1
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("ford"))));

        // That idx is 6
        next = pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING);
        assertEq(next, 6, "next idx");

        // From there the counter of '5' starts before we return nothing to provision
        (strategy, idx) = pufferProtocol.getNextValidatorToProvision();
        assertEq(strategy, NO_RESTAKING, "strategy");
        assertEq(idx, 8, "idx");
    }

    // // Test extending validator commitment
    // function testExtendCommitment() public {
    //     _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

    //     Validator memory validator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 0);
    //     assertTrue(validator.node == address(this), "node operator");

    //     uint256 firstPayment = validator.commitmentExpiration;
    //     assertEq(firstPayment, block.timestamp + 30 days, "lastPayment");

    //     vm.warp(1000);

    //     vm.expectRevert();
    //     pufferProtocol.extendCommitment{ value: 0 }(NO_RESTAKING, 0);

    //     vm.expectRevert(IPufferProtocol.InvalidETHAmount.selector);
    //     pufferProtocol.extendCommitment{ value: 5 ether }(NO_RESTAKING, 0);

    //     pufferProtocol.extendCommitment{ value: pufferProtocol.getSmoothingCommitment(NO_RESTAKING) }(NO_RESTAKING, 0);

    //     validator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 0);

    //     assertTrue(validator.commitmentExpiration == block.timestamp + 30 days, "lastPayment");
    // }

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
        vm.expectRevert(IPufferProtocol.OutsideUpdateWindow.selector);
        pufferProtocol.proofOfReserve({
            ethAmount: 2 ether,
            lockedETH: 0,
            pufETHTotalSupply: 1 ether,
            blockNumber: 50401
        });
    }

    // Set validator limit and try registering that many validators
    function testFuzzRegisterManyValidators(uint8 numberOfValidatorsToProvision) external {
        pufferProtocol.setValidatorLimitPerInterval(numberOfValidatorsToProvision);
        for (uint256 i = 0; i < uint256(numberOfValidatorsToProvision); ++i) {
            vm.deal(address(this), 2 ether);
            _registerValidatorKey(bytes32(i), NO_RESTAKING);
        }
    }

    // Change smoothing commitment for default strategy
    function testSetSmoothingCommitment() external {
        uint256 commitmentBefore = pufferProtocol.getSmoothingCommitment(1);
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 20 ether;
        pufferProtocol.setSmoothingCommitments(commitments);
        uint256 commitmentAfter = pufferProtocol.getSmoothingCommitment(1);
        assertEq(commitmentAfter, 20 ether, "after");
        assertTrue(commitmentBefore != commitmentAfter, "should change");
    }

    // Change smoothing non existent strategy
    function testSetSmoothingCommitment(bytes32 strategy) external {
        uint256 commitmentBefore = pufferProtocol.getSmoothingCommitment(1);
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 20 ether;
        pufferProtocol.setSmoothingCommitments(commitments);
        uint256 commitmentAfter = pufferProtocol.getSmoothingCommitment(1);
        assertEq(commitmentAfter, 20 ether, "after");
        assertTrue(commitmentBefore != commitmentAfter, "should change");
    }

    // Try registering without RAVE evidence
    function testRegisterWithoutRAVE() public {
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(1);

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
            blsPubKeySet: new bytes(48),
            raveEvidence: new bytes(0) // No rave
         });

        pufferProtocol.registerValidatorKey{ value: smoothingCommitment + 2 ether }(validatorData, NO_RESTAKING, 1);
    }

    // Try registering with invalid BLS key length
    function testRegisterWithInvalidBLSPubKey() public {
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(1);

        bytes memory pubKey = hex"aeaa";

        bytes[] memory newSetOfPubKeys = new bytes[](3);

        // we have 3 guardians in TestHelper.sol
        newSetOfPubKeys[0] = bytes("key1");
        newSetOfPubKeys[0] = bytes("key2");
        newSetOfPubKeys[0] = bytes("key3");

        ValidatorKeyData memory validatorData = ValidatorKeyData({
            blsPubKey: pubKey, // key length is small
            signature: new bytes(0),
            depositDataRoot: bytes32(""),
            blsEncryptedPrivKeyShares: new bytes[](3),
            blsPubKeySet: new bytes(144),
            raveEvidence: new bytes(1)
        });

        vm.expectRevert(IPufferProtocol.InvalidBLSPubKey.selector);
        pufferProtocol.registerValidatorKey{ value: smoothingCommitment }(validatorData, NO_RESTAKING, 1);
    }

    function testGetPayload() public {
        (bytes[] memory guardianPubKeys, bytes memory withdrawalCredentials, uint256 threshold, uint256 ethAmount) =
            pufferProtocol.getPayload(NO_RESTAKING, false, 1);

        assertEq(guardianPubKeys[0], guardian1EnclavePubKey, "guardian1");
        assertEq(guardianPubKeys[1], guardian2EnclavePubKey, "guardian2");
        assertEq(guardianPubKeys[2], guardian3EnclavePubKey, "guardian3");

        assertEq(guardianPubKeys.length, 3, "pubkeys len");
        assertEq(threshold, 1, "threshold");
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
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(1);
        bytes memory pubKey = _getPubKey(bytes32("charlie"));
        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        vm.expectRevert(IPufferProtocol.ValidatorLimitPerIntervalReached.selector);
        pufferProtocol.registerValidatorKey{ value: smoothingCommitment }(validatorKeyData, NO_RESTAKING, 1);
    }

    function testSetProtocolFeeRate() public {
        uint256 rate = 10 * FixedPointMathLib.WAD;
        pufferProtocol.setProtocolFeeRate(rate); // 10%
        assertEq(pufferProtocol.getProtocolFeeRate(), rate, "new rate");
    }

    function testSetGuardiansFeeRateOverTheLimit() public {
        uint256 rate = 30 * FixedPointMathLib.WAD;
        vm.expectRevert(IPufferProtocol.InvalidData.selector);
        pufferProtocol.setGuardiansFeeRate(rate);
    }

    function testSetProtocolFeeRateOverTheLimit() public {
        uint256 rate = 30 * FixedPointMathLib.WAD;
        vm.expectRevert(IPufferProtocol.InvalidData.selector);
        pufferProtocol.setProtocolFeeRate(rate);
    }

    function testSetWithdrawalPoolRateOverTheLimit() public {
        uint256 rate = 30 * FixedPointMathLib.WAD;
        vm.expectRevert(IPufferProtocol.InvalidData.selector);
        pufferProtocol.setWithdrawalPoolRate(rate);
    }

    function testChangeStrategy() public {
        address strategy = pufferProtocol.getStrategyAddress(NO_RESTAKING);
        vm.expectRevert(IPufferProtocol.InvalidPufferStrategy.selector);
        pufferProtocol.changeStrategy(NO_RESTAKING, PufferStrategy(payable(address(5))));
    }

    function testChangeStrategyToCustom() public {
        pufferProtocol.changeStrategy(bytes32("RANDOM_STRATEGY"), PufferStrategy(payable(address(5))));
        address strategyAfterChange = pufferProtocol.getStrategyAddress("RANDOM_STRATEGY");
        assertTrue(address(0) != strategyAfterChange, "strategy did not change");
    }

    function _registerValidatorKey(bytes32 pubKeyPart, bytes32 strategyName) internal {
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(1);

        bytes memory pubKey = _getPubKey(pubKeyPart);

        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, strategyName);

        uint256 idx = pufferProtocol.getPendingValidatorIndex(strategyName);

        uint256 bond = 1 ether;

        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, idx, strategyName, true);
        pufferProtocol.registerValidatorKey{ value: (smoothingCommitment + bond) }(validatorKeyData, strategyName, 1);
    }

    function testStopRegistration() public {
        vm.deal(address(pool), 100 ether);

        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("bob"), NO_RESTAKING);

        assertEq(pool.balanceOf(address(pufferProtocol)), 2 ether, "pool should have the bond amount for 2 validators");

        vm.prank(address(4123123)); // random sender
        vm.expectRevert(Unauthorized.selector);
        pufferProtocol.stopRegistration(NO_RESTAKING, 0);

        (bytes32 strategyName, uint256 idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(strategyName, NO_RESTAKING, "strategy");
        assertEq(0, idx, "strategy");
        assertEq(pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING), 0, "zero index is next in line");

        bytes memory alicePubKey = _getPubKey(bytes32("alice"));

        vm.expectEmit(true, true, true, true);
        emit ValidatorDequeued(alicePubKey, 0);
        pufferProtocol.stopRegistration(NO_RESTAKING, 0);

        assertEq(pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING), 1, "1 index is next in line");

        assertEq(pool.balanceOf(address(pufferProtocol)), 1 ether, "pool should have the bond amount for 1 validators");
        // Because this contract is msg.sender, it means that it is the node operator
        assertEq(pool.balanceOf(address(this)), 1 ether, "node operator should get 1 pufETH for Alice");

        (strategyName, idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(strategyName, NO_RESTAKING, "strategy after");
        assertEq(1, idx, "strategy after");

        bytes[] memory signatures = _getGuardianSignatures(alicePubKey);

        // Unauthorized, because the protocol is expecting signature for bob
        vm.expectRevert(Unauthorized.selector);
        pufferProtocol.provisionNode(signatures);

        // Bob should be provisioned next
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("bob"))));

        // Invalid status
        vm.expectRevert(abi.encodeWithSelector(IPufferProtocol.InvalidValidatorState.selector, Status.DEQUEUED));
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

        vm.deal(address(pool), 1000 ether);

        vm.startPrank(address(guardiansSafe));
        // // 1. provision zero key
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(zeroPubKey, 0, NO_RESTAKING);
        pufferProtocol.provisionNode(_getGuardianSignatures(zeroPubKey));

        // Provision Bob that is not zero pubKey
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(bobPubKey, 1, NO_RESTAKING);
        pufferProtocol.provisionNode(_getGuardianSignatures(bobPubKey));

        Validator memory bobValidator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 1);

        assertTrue(bobValidator.status == Status.ACTIVE, "bob should be active");

        pufferProtocol.skipProvisioning(NO_RESTAKING);

        emit SuccesfullyProvisioned(zeroPubKey, 3, NO_RESTAKING);
        pufferProtocol.provisionNode(_getGuardianSignatures(zeroPubKey));
    }

    function testProvisionNode() public {
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

        vm.startPrank(address(guardiansSafe));

        // Provision Bob that is not zero pubKey
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("bob")), 0, NO_RESTAKING);
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("bob"))));

        (nextStrategy, nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextStrategy == EIGEN_DA, "strategy selection");
        // Id is zero, because that is the first in this queue
        assertTrue(nextId == 0, "strategy id");

        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("benjamin")), 0, EIGEN_DA);
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("benjamin"))));

        (nextStrategy, nextId) = pufferProtocol.getNextValidatorToProvision();

        // // Because the EIGEN_DA queue is empty, the next for provisioning is from CRAZY_GAINS
        assertTrue(nextStrategy == CRAZY_GAINS, "strategy selection");
        assertTrue(nextId == 0, "strategy id");

        vm.stopPrank();

        // Now jason registers to EIGEN_DA
        _registerValidatorKey(bytes32("jason"), EIGEN_DA);

        vm.startPrank(address(guardiansSafe));

        // If we query next validator, it should switch back to EIGEN_DA (because of the weighted selection)
        (nextStrategy, nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextStrategy == EIGEN_DA, "strategy selection");
        assertTrue(nextId == 1, "strategy id");

        // Provisioning of rocky should fail, because jason is next in line
        bytes[] memory signatures = _getGuardianSignatures(_getPubKey(bytes32("rocky")));
        vm.expectRevert(Unauthorized.selector);
        pufferProtocol.provisionNode(signatures);

        // Provision Jason
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("jason"))));

        (nextStrategy, nextId) = pufferProtocol.getNextValidatorToProvision();

        // Rocky is now in line
        assertTrue(nextStrategy == CRAZY_GAINS, "strategy selection");
        assertTrue(nextId == 0, "strategy id");
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("rocky"))));

        (nextStrategy, nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextStrategy == NO_RESTAKING, "strategy selection");
        assertTrue(nextId == 1, "strategy id");

        assertEq(
            pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING), 1, "next idx for no restaking strategy"
        );

        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("alice")), 1, NO_RESTAKING);
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))));
    }

    function testCreatePufferStrategy() public {
        pufferProtocol.createPufferStrategy(bytes32("LEVERAGED_RESTAKING"));
    }

    function testClaimBackBond() public {
        // In our test case, we are posting roots and simulating a full withdrawal before the validator registration
        _setupMerkleRoot();

        // For us to test the withdrawal from the node operator, we must register and provision that validator
        // In our case we have 2 validators NO_RESTAKING and EIGEN_DA

        address alice = makeAddr("alice");
        vm.deal(alice, 5 ether);
        address bob = makeAddr("bob");
        vm.deal(bob, 5 ether);
        vm.deal(address(pool), 100 ether);

        assertEq(pool.balanceOf(address(pufferProtocol)), 0, "0 pufETH in protocol");

        // Create validators
        vm.startPrank(alice);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        vm.startPrank(bob);
        _registerValidatorKey(bytes32("bob"), EIGEN_DA);

        // PufferProtocol should hold pufETH (bond for 2 validators)
        assertEq(pool.balanceOf(address(pufferProtocol)), 2 ether, "2 pufETH in protocol");

        // Provision validators
        vm.startPrank(address(guardiansSafe));
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))));
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("bob"))));

        bytes32[] memory aliceProof = new bytes32[](1);
        aliceProof[0] = hex"0e4f14a17378337442fec9c0fe64e67c22f046a5fd1fc973859da0abeb6323e2";

        // Now the node operators submit proofs to get back their bond
        vm.startPrank(alice);
        // Invalid block number = invalid proof
        vm.expectRevert(abi.encodeWithSelector(IPufferProtocol.InvalidMerkleProof.selector));
        pufferProtocol.stopValidator({
            strategyName: NO_RESTAKING,
            validatorIndex: 0,
            blockNumber: 150,
            withdrawalAmount: 32.14 ether,
            wasSlashed: false,
            merkleProof: aliceProof
        });

        assertEq(pool.balanceOf(alice), 0, "alice has zero pufETH");

        // Valid proof
        pufferProtocol.stopValidator({
            strategyName: NO_RESTAKING,
            validatorIndex: 0,
            blockNumber: 100,
            withdrawalAmount: 32.14 ether,
            wasSlashed: false,
            merkleProof: aliceProof
        });

        assertEq(pool.balanceOf(alice), 1 ether, "alice received back the bond in pufETH");

        bytes32[] memory bobProof = new bytes32[](1);
        bobProof[0] = hex"6df1a3c785f77eb353a2a4c0d38629c4d4088032e8ec0695b9bbbee2bd9d4506";

        assertEq(pool.balanceOf(bob), 0, "bob has zero pufETH");

        // Bob was slashed, bob shouldn't get any pufETH
        pufferProtocol.stopValidator({
            strategyName: EIGEN_DA,
            validatorIndex: 0,
            blockNumber: 100,
            withdrawalAmount: 31 ether,
            wasSlashed: true,
            merkleProof: bobProof
        });

        assertEq(pool.balanceOf(bob), 0, "bob has zero pufETH after");
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

    function testPause() public {
        pool.depositETH{ value: 1 ether }();

        vm.startPrank(_broadcaster); // Admin
        // Pause
        accessManager.setTargetClosed(address(pool), true);
        vm.stopPrank();

        vm.expectRevert();
        pool.depositETH{ value: 1 ether }();
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
            pubKey,
            validator.signature,
            withdrawalCredentials,
            pufferProtocol.getDepositDataRoot({
                pubKey: pubKey,
                signature: validator.signature,
                withdrawalCredentials: withdrawalCredentials
            })
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

    function _getMockValidatorKeyData(bytes memory pubKey, bytes32 strategyName)
        internal
        view
        returns (ValidatorKeyData memory)
    {
        bytes[] memory newSetOfPubKeys = new bytes[](3);

        // we have 3 guardians in TestHelper.sol
        newSetOfPubKeys[0] = bytes("key1");
        newSetOfPubKeys[0] = bytes("key2");
        newSetOfPubKeys[0] = bytes("key3");

        address strategy = pufferProtocol.getStrategyAddress(strategyName);

        bytes memory withdrawalCredentials = pufferProtocol.getWithdrawalCredentials(strategy);

        bytes memory randomSignature =
            hex"8aa088146c8c6ca6d8ad96648f20e791be7c449ce7035a6bd0a136b8c7b7867f730428af8d4a2b69658bfdade185d6110b938d7a59e98d905e922d53432e216dc88c3384157d74200d3f2de51d31737ce19098ff4d4f54f77f0175e23ac98da5";

        ValidatorKeyData memory validatorData = ValidatorKeyData({
            blsPubKey: pubKey, // key length must be 48 byte
            // mock signature copied from some random deposit transaction
            signature: randomSignature,
            depositDataRoot: pufferProtocol.getDepositDataRoot({
                pubKey: pubKey,
                signature: randomSignature,
                withdrawalCredentials: withdrawalCredentials
            }),
            blsEncryptedPrivKeyShares: new bytes[](3),
            blsPubKeySet: new bytes(48),
            raveEvidence: new bytes(1) // Guardians are checking it off chain
         });

        return validatorData;
    }

    function _getPubKey(bytes32 pubKeypart) internal pure returns (bytes memory) {
        return bytes.concat(abi.encodePacked(pubKeypart), bytes16(""));
    }

    // Sets the merkle root and makes sure that the funds get split between WithdrawalPool and PufferPool ASAP
    function _setupMerkleRoot() public {
        // Create EIGEN_DA strategy
        pufferProtocol.createPufferStrategy(EIGEN_DA);

        // Include the EIGEN_DA in strategy selection
        bytes32[] memory newWeights = new bytes32[](4);
        newWeights[0] = NO_RESTAKING;
        newWeights[1] = EIGEN_DA;
        newWeights[2] = EIGEN_DA;
        newWeights[3] = CRAZY_GAINS;

        pufferProtocol.setStrategyWeights(newWeights);

        address noRestakingStrategy = pufferProtocol.getStrategyAddress(NO_RESTAKING);
        address eigenDaStrategy = pufferProtocol.getStrategyAddress(EIGEN_DA);

        // Enable PufferProtocol to call `call` function on strategy
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IPufferStrategy.call.selector;
        vm.startPrank(_broadcaster);
        accessManager.setTargetFunctionRole(noRestakingStrategy, selectors, ROLE_ID_PUFFER_PROTOCOL);
        accessManager.setTargetFunctionRole(eigenDaStrategy, selectors, ROLE_ID_PUFFER_PROTOCOL);
        vm.stopPrank();

        // We are simulating 2 full withdrawals
        address[] memory strategies = new address[](2);
        strategies[0] = noRestakingStrategy;
        strategies[1] = eigenDaStrategy;

        // Give funds to strategies
        vm.deal(strategies[0], 200 ether);
        vm.deal(strategies[1], 100 ether);

        // Amounts of full withdrawals that we want to move from strategies to pools
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 32.14 ether;
        amounts[1] = 31 ether;

        // Assert starting state of the pools
        assertEq(address(pool).balance, 0, "starting pool balance");
        assertEq(address(withdrawalPool).balance, 0, "starting withdraawal pool balance");

        // Values are hardcoded and generated using test/unit/FullWithdrawalProofs.js
        vm.startPrank(address(guardiansSafe));
        pufferProtocol.postFullWithdrawalsRoot({
            root: hex"56a62fc9845bdfebe4127e8d9d67ea0c90fc0ac98d75747baff454b85ebb3df9",
            blockNumber: 100,
            strategies: strategies,
            amounts: amounts
        });
        vm.stopPrank();

        // Total withdrawal eth is 32.14 + 31

        // Default split rate for withdrawal pool is 10%
        // 10% of 32.14 + 31 = 6.314
        // The rest is 63.14 - 6.314 = 56.826

        assertEq(address(withdrawalPool).balance, 6.314 ether, "ending withdraawal pool balance");
        assertEq(address(pool).balance, 56.826 ether, "ending pool balance");
    }
}
