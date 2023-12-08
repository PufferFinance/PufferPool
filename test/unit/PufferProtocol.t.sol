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
import { PufferModule } from "puffer/PufferModule.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { ROLE_ID_DAO, ROLE_ID_PUFFER_PROTOCOL } from "script/SetupAccess.s.sol";
import { Unauthorized } from "puffer/Errors.sol";
import { LibGuardianMessages } from "puffer/LibGuardianMessages.sol";
import { Permit } from "puffer/struct/Permit.sol";
import { Merkle } from "murky/Merkle.sol";

contract PufferProtocolTest is TestHelper {
    using ECDSA for bytes32;

    Merkle fullWithdrawalsMerkleProof;
    bytes32[] fullWithdrawalMerkleProofData;

    event ValidatorKeyRegistered(bytes indexed pubKey, uint256 indexed, bytes32 indexed, bool);
    event SuccesfullyProvisioned(bytes indexed pubKey, uint256 indexed, bytes32 indexed);
    event FailedToProvision(bytes indexed pubKey, uint256);
    event ValidatorDequeued(bytes indexed pubKey, uint256 validatorIndex);
    event ModuleWeightsChanged(bytes32[] oldWeights, bytes32[] newWeights);

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
        selectors[2] = PufferProtocol.createPufferModule.selector;
        selectors[3] = PufferProtocol.setModuleWeights.selector;
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
        assertTrue(address(pufferProtocol.WITHDRAWAL_POOL()) != address(0), "non zero address");
        assertTrue(address(pufferProtocol.POOL()) != address(0), "pufer pool address");
        address module = pufferProtocol.getModuleAddress(NO_RESTAKING);
        assertEq(PufferModule(payable(module)).NAME(), NO_RESTAKING, "bad name");
    }

    function testEmptyQueue() public {
        (bytes32 moduleName, uint256 idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(moduleName, bytes32("NO_VALIDATORS"), "name");
        assertEq(idx, type(uint256).max, "name");
    }

    // Test Skipping the validator
    function testSkipProvisioning() public {
        vm.deal(address(pool), 1000 ether);

        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("bob"), NO_RESTAKING);

        (bytes32 moduleName, uint256 idx) = pufferProtocol.getNextValidatorToProvision();
        uint256 moduleSelecitonIdx = pufferProtocol.getModuleSelectIndex();

        assertEq(moduleName, NO_RESTAKING, "module");
        assertEq(idx, 0, "idx");
        assertEq(moduleSelecitonIdx, 0, "module selection idx");

        assertTrue(pool.balanceOf(address(this)) == 0, "zero pufETH");

        pufferProtocol.skipProvisioning(NO_RESTAKING, _getGuardianSignaturesForSkipping());

        // This contract shluld receive pufETH because of the skipProvisioning
        assertTrue(pool.balanceOf(address(this)) != 0, "non zero pufETH");

        Validator memory aliceValidator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 0);
        assertTrue(aliceValidator.status == Status.SKIPPED, "did not update status");

        (moduleName, idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(moduleName, NO_RESTAKING, "module");
        assertEq(idx, 1, "idx should be 1");

        bytes[] memory signatures = _getGuardianSignatures(_getPubKey(bytes32("bob")));

        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("bob")), 1, NO_RESTAKING);
        pufferProtocol.provisionNode(signatures);
        moduleSelecitonIdx = pufferProtocol.getModuleSelectIndex();
        assertEq(moduleSelecitonIdx, 1, "module idx changed");
    }

    // Create an existing module should revert
    function testCreateExistingModuleShouldFail() public {
        vm.startPrank(DAO);
        vm.expectRevert(IPufferProtocol.ModuleAlreadyExists.selector);
        pufferProtocol.createPufferModule(NO_RESTAKING);
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

    // Try registering with invalid module
    function testRegisterToInvalidModule() public {
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(1);
        bytes memory pubKey = _getPubKey(bytes32("charlie"));
        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        vm.expectRevert(IPufferProtocol.ValidatorLimitForModuleReached.selector);
        pufferProtocol.registerValidatorKey{ value: smoothingCommitment }(
            validatorKeyData, bytes32("imaginary module"), 1
        );
    }

    // Try registering with invalid amount paid
    function testRegisterWithInvalidAmountPaid() public {
        bytes memory pubKey = _getPubKey(bytes32("charlie"));
        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        vm.expectRevert(IPufferProtocol.InvalidETHAmount.selector);
        pufferProtocol.registerValidatorKey{ value: 5 ether }(validatorKeyData, NO_RESTAKING, 1);
    }

    function testModuleDOS() external {
        vm.deal(address(pool), 1000 ether);

        bytes32[] memory weights = pufferProtocol.getModuleWeights();
        assertEq(weights.length, 1, "only one module");
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

        (bytes32 module, uint256 idx) = pufferProtocol.getNextValidatorToProvision();
        assertEq(module, NO_RESTAKING, "module");
        assertEq(idx, 0, "idx");

        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))));

        uint256 next = pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING);
        assertEq(next, 1, "next idx");

        (module, idx) = pufferProtocol.getNextValidatorToProvision();
        assertEq(module, NO_RESTAKING, "module");
        assertEq(idx, 5, "idx");

        // Provision node updates the idx to current + 1
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("ford"))));

        // That idx is 6
        next = pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING);
        assertEq(next, 6, "next idx");

        // From there the counter of '5' starts before we return nothing to provision
        (module, idx) = pufferProtocol.getNextValidatorToProvision();
        assertEq(module, NO_RESTAKING, "module");
        assertEq(idx, 8, "idx");
    }

    // Test extending validator commitment
    function testExtendCommitment() public {
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        Validator memory validator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 0);
        assertTrue(validator.node == address(this), "node operator");

        vm.warp(1000);

        // Amounts dont match
        vm.expectRevert(IPufferProtocol.InvalidETHAmount.selector);
        pufferProtocol.extendCommitment{ value: 5 ether }(NO_RESTAKING, 0, 5);

        // Should extend
        pufferProtocol.extendCommitment{ value: pufferProtocol.getSmoothingCommitment(5) }(NO_RESTAKING, 0, 5);

        validator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 0);

        assertTrue(validator.monthsCommitted == 5, "lastPayment");
    }

    // Try updating for future block
    function testProofOfReserve() external {
        vm.roll(50401);

        pufferProtocol.proofOfReserve({
            ethAmount: 2 ether,
            lockedETH: 32 ether,
            pufETHTotalSupply: 1 ether,
            blockNumber: 50401,
            numberOfActiveValidators: 100,
            guardianSignatures: _getGuardianEOASignatures(
                LibGuardianMessages._getProofOfReserveMessage({
                    ethAmount: 2 ether,
                    lockedETH: 32 ether,
                    numberOfActiveValidators: 100,
                    pufETHTotalSupply: 1 ether,
                    blockNumber: 50401
                })
                )
        });

        bytes[] memory signatures2 = _getGuardianEOASignatures(
            LibGuardianMessages._getProofOfReserveMessage({
                ethAmount: 2 ether,
                lockedETH: 0 ether,
                numberOfActiveValidators: 100,
                pufETHTotalSupply: 1 ether,
                blockNumber: 50401
            })
        );

        // Second update should revert as it has not passed enough time between two updates
        vm.expectRevert(IPufferProtocol.OutsideUpdateWindow.selector);
        pufferProtocol.proofOfReserve({
            ethAmount: 2 ether,
            lockedETH: 0,
            pufETHTotalSupply: 1 ether,
            blockNumber: 50401,
            numberOfActiveValidators: 100,
            guardianSignatures: signatures2
        });
    }

    function testBurstThreshold() external {
        vm.roll(50401);

        // Update the reserves and make it so that the next validator is over threshold
        pufferProtocol.proofOfReserve({
            ethAmount: 2 ether,
            lockedETH: 32 ether,
            pufETHTotalSupply: 1 ether,
            blockNumber: 50401,
            numberOfActiveValidators: 1,
            guardianSignatures: _getGuardianEOASignatures(
                LibGuardianMessages._getProofOfReserveMessage({
                    ethAmount: 2 ether,
                    lockedETH: 32 ether,
                    pufETHTotalSupply: 1 ether,
                    blockNumber: 50401,
                    numberOfActiveValidators: 1
                })
                )
        });

        uint256 balanceBefore = pufferProtocol.TREASURY().balance;

        uint256 sc = pufferProtocol.getSmoothingCommitment(1);

        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        uint256 balanceAfter = pufferProtocol.TREASURY().balance;

        assertEq(balanceAfter, balanceBefore + sc, "treasury gets everything");
    }

    // Set validator limit and try registering that many validators
    function testFuzzRegisterManyValidators(uint8 numberOfValidatorsToProvision) external {
        pufferProtocol.setValidatorLimitPerInterval(numberOfValidatorsToProvision);
        for (uint256 i = 0; i < uint256(numberOfValidatorsToProvision); ++i) {
            vm.deal(address(this), 2 ether);
            _registerValidatorKey(bytes32(i), NO_RESTAKING);
        }
    }

    // Change smoothing commitment for default module
    function testSetSmoothingCommitment() external {
        uint256 commitmentBefore = pufferProtocol.getSmoothingCommitment(1);
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 20 ether;
        pufferProtocol.setSmoothingCommitments(commitments);
        uint256 commitmentAfter = pufferProtocol.getSmoothingCommitment(1);
        assertEq(commitmentAfter, 20 ether, "after");
        assertTrue(commitmentBefore != commitmentAfter, "should change");
    }

    // Change smoothing non existent module
    function testSetSmoothingCommitment(bytes32 module) external {
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

    // Try to provision a validator when there is nothing to provision
    function testProvisioning() public {
        (bytes32 moduleName, uint256 idx) = pufferProtocol.getNextValidatorToProvision();
        assertEq(type(uint256).max, idx, "module");

        bytes[] memory signatures =
            _getGuardianSignatures(hex"0000000000000000000000000000000000000000000000000000000000000000");

        vm.expectRevert();
        pufferProtocol.provisionNode(signatures);
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

    function testSetWithdrawalPoolRateMax() public {
        uint256 rate = 100 * FixedPointMathLib.WAD;
        vm.expectEmit(true, true, true, true);
        emit IPufferProtocol.WithdrawalPoolRateChanged(10 * FixedPointMathLib.WAD, 100 * FixedPointMathLib.WAD);
        pufferProtocol.setWithdrawalPoolRate(rate);
    }

    function testFeeCalculations() public {
        // Default values are
        // 2% guardians
        // 10% withdrawal fee pool
        // 0.5% guardians
        // rest to the PufferPool
        uint256 amount = pufferProtocol.getSmoothingCommitment(12);

        assertEq(0, pufferProtocol.TREASURY().balance, "zero treasury");
        assertEq(0, address(pufferProtocol.GUARDIAN_MODULE()).balance, "zero guardians");
        assertEq(0, address(pufferProtocol.POOL()).balance, "zero pool");
        assertEq(0, address(pufferProtocol.WITHDRAWAL_POOL()).balance, "withdrawal pool balance");

        // We don't have additional validations on if the validator is active or not
        pufferProtocol.extendCommitment{ value: amount }(NO_RESTAKING, 0, 12);

        assertEq(2280296714778796, pufferProtocol.TREASURY().balance, "non zero treasury");
        assertEq(570074178694699, address(pufferProtocol.GUARDIAN_MODULE()).balance, "non zero guardians");
        assertEq(11116446484546631, address(pufferProtocol.WITHDRAWAL_POOL()).balance, "withdrawal pool balance");
        assertEq(100048018360919684, address(pufferProtocol.POOL()).balance, "non zero pool");
    }

    function testFeeCalculationsEverythingToWithdrawalPool() public {
        // Set withdrawal fee to 100%
        pufferProtocol.setWithdrawalPoolRate(100 * FixedPointMathLib.WAD);

        // Default values are
        // 2% guardians
        // 0.5% guardians
        // 100% to the withdrawal pool
        // 0 to puffer pool
        uint256 amount = pufferProtocol.getSmoothingCommitment(12);

        assertEq(0, pufferProtocol.TREASURY().balance, "zero treasury");
        assertEq(0, address(pufferProtocol.GUARDIAN_MODULE()).balance, "zero guardians");
        assertEq(0, address(pufferProtocol.POOL()).balance, "zero pool");

        // We don't have additional validations on if the validator is active or not
        pufferProtocol.extendCommitment{ value: amount }(NO_RESTAKING, 0, 12);

        assertEq(2280296714778796, pufferProtocol.TREASURY().balance, "non zero treasury");
        assertEq(570074178694699, address(pufferProtocol.GUARDIAN_MODULE()).balance, "non zero guardians");
        assertEq(111164464845466315, address(pufferProtocol.WITHDRAWAL_POOL()).balance, "non zero withdrawal pool");
        assertEq(0, address(pufferProtocol.POOL()).balance, "zero puffer pool");
    }

    function testFeeCalculationsEverythingToPufferPool() public {
        // Set withdrawal fee to 100%
        pufferProtocol.setWithdrawalPoolRate(0);

        // Default values are
        // 2% guardians
        // 0.5% guardians
        // 0% to the withdrawal pool
        // 100% to puffer pool
        uint256 amount = pufferProtocol.getSmoothingCommitment(12);

        assertEq(0, pufferProtocol.TREASURY().balance, "zero treasury");
        assertEq(0, address(pufferProtocol.GUARDIAN_MODULE()).balance, "zero guardians");
        assertEq(0, address(pufferProtocol.POOL()).balance, "zero pool");

        // We don't have additional validations on if the validator is active or not
        pufferProtocol.extendCommitment{ value: amount }(NO_RESTAKING, 0, 12);

        assertEq(2280296714778796, pufferProtocol.TREASURY().balance, "non zero treasury");
        assertEq(570074178694699, address(pufferProtocol.GUARDIAN_MODULE()).balance, "non zero guardians");
        assertEq(0, address(pufferProtocol.WITHDRAWAL_POOL()).balance, "non zero withdrawal pool");
        assertEq(111164464845466315, address(pufferProtocol.POOL()).balance, "zero puffer pool");
    }

    function testChangeModule() public {
        vm.expectRevert(IPufferProtocol.InvalidPufferModule.selector);
        pufferProtocol.changeModule(NO_RESTAKING, PufferModule(payable(address(5))));
    }

    function testChangeModuleToCustom() public {
        pufferProtocol.changeModule(bytes32("RANDOM_MODULE"), PufferModule(payable(address(5))));
        address moduleAfterChange = pufferProtocol.getModuleAddress("RANDOM_MODULE");
        assertTrue(address(0) != moduleAfterChange, "module did not change");
    }

    function _registerValidatorKey(bytes32 pubKeyPart, bytes32 moduleName) internal {
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(1);

        bytes memory pubKey = _getPubKey(pubKeyPart);

        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, moduleName);

        uint256 idx = pufferProtocol.getPendingValidatorIndex(moduleName);

        uint256 bond = 1 ether;

        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, idx, moduleName, true);
        pufferProtocol.registerValidatorKey{ value: (smoothingCommitment + bond) }(validatorKeyData, moduleName, 1);
    }

    function testStopRegistration() public {
        vm.deal(address(pool), 100 ether);

        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("bob"), NO_RESTAKING);

        assertEq(pool.balanceOf(address(pufferProtocol)), 2 ether, "pool should have the bond amount for 2 validators");

        vm.prank(address(4123123)); // random sender
        vm.expectRevert(Unauthorized.selector);
        pufferProtocol.stopRegistration(NO_RESTAKING, 0);

        (bytes32 moduleName, uint256 idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(moduleName, NO_RESTAKING, "module");
        assertEq(0, idx, "module");
        assertEq(pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING), 0, "zero index is next in line");

        bytes memory alicePubKey = _getPubKey(bytes32("alice"));

        vm.expectEmit(true, true, true, true);
        emit ValidatorDequeued(alicePubKey, 0);
        pufferProtocol.stopRegistration(NO_RESTAKING, 0);

        assertEq(pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING), 1, "1 index is next in line");

        assertEq(pool.balanceOf(address(pufferProtocol)), 1 ether, "pool should have the bond amount for 1 validators");
        // Because this contract is msg.sender, it means that it is the node operator
        assertEq(pool.balanceOf(address(this)), 1 ether, "node operator should get 1 pufETH for Alice");

        (moduleName, idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(moduleName, NO_RESTAKING, "module after");
        assertEq(1, idx, "module after");

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

        bytes[] memory signatures = _getGuardianSignatures(zeroPubKey);

        // // 1. provision zero key
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(zeroPubKey, 0, NO_RESTAKING);
        pufferProtocol.provisionNode(signatures);

        bytes[] memory bobSignatures = _getGuardianSignatures(bobPubKey);

        // Provision Bob that is not zero pubKey
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(bobPubKey, 1, NO_RESTAKING);
        pufferProtocol.provisionNode(bobSignatures);

        Validator memory bobValidator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 1);

        assertTrue(bobValidator.status == Status.ACTIVE, "bob should be active");

        pufferProtocol.skipProvisioning(NO_RESTAKING, _getGuardianSignaturesForSkipping());

        signatures = _getGuardianSignatures(zeroPubKey);

        emit SuccesfullyProvisioned(zeroPubKey, 3, NO_RESTAKING);
        pufferProtocol.provisionNode(signatures);
    }

    function testProvisionNode() public {
        pufferProtocol.createPufferModule(EIGEN_DA);
        pufferProtocol.createPufferModule(CRAZY_GAINS);

        bytes32[] memory oldWeights = new bytes32[](1);
        oldWeights[0] = NO_RESTAKING;

        bytes32[] memory newWeights = new bytes32[](4);
        newWeights[0] = NO_RESTAKING;
        newWeights[1] = EIGEN_DA;
        newWeights[2] = EIGEN_DA;
        newWeights[3] = CRAZY_GAINS;

        vm.expectEmit(true, true, true, true);
        emit ModuleWeightsChanged(oldWeights, newWeights);
        pufferProtocol.setModuleWeights(newWeights);

        vm.deal(address(pool), 10000 ether);

        _registerValidatorKey(bytes32("bob"), NO_RESTAKING);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("charlie"), NO_RESTAKING);
        _registerValidatorKey(bytes32("david"), NO_RESTAKING);
        _registerValidatorKey(bytes32("emma"), NO_RESTAKING);
        _registerValidatorKey(bytes32("benjamin"), EIGEN_DA);
        _registerValidatorKey(bytes32("rocky"), CRAZY_GAINS);

        (bytes32 nextModule, uint256 nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextModule == NO_RESTAKING, "module selection");
        assertTrue(nextId == 0, "module selection");

        bytes[] memory signatures = _getGuardianSignatures(_getPubKey(bytes32("bob")));

        // Provision Bob that is not zero pubKey
        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("bob")), 0, NO_RESTAKING);
        pufferProtocol.provisionNode(signatures);

        (nextModule, nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextModule == EIGEN_DA, "module selection");
        // Id is zero, because that is the first in this queue
        assertTrue(nextId == 0, "module id");

        signatures = _getGuardianSignatures(_getPubKey(bytes32("benjamin")));

        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("benjamin")), 0, EIGEN_DA);
        pufferProtocol.provisionNode(signatures);

        (nextModule, nextId) = pufferProtocol.getNextValidatorToProvision();

        // // Because the EIGEN_DA queue is empty, the next for provisioning is from CRAZY_GAINS
        assertTrue(nextModule == CRAZY_GAINS, "module selection");
        assertTrue(nextId == 0, "module id");

        vm.stopPrank();

        // Now jason registers to EIGEN_DA
        _registerValidatorKey(bytes32("jason"), EIGEN_DA);

        // If we query next validator, it should switch back to EIGEN_DA (because of the weighted selection)
        (nextModule, nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextModule == EIGEN_DA, "module selection");
        assertTrue(nextId == 1, "module id");

        // Provisioning of rocky should fail, because jason is next in line
        signatures = _getGuardianSignatures(_getPubKey(bytes32("rocky")));
        vm.expectRevert(Unauthorized.selector);
        pufferProtocol.provisionNode(signatures);

        signatures = _getGuardianSignatures(_getPubKey(bytes32("jason")));

        // Provision Jason
        pufferProtocol.provisionNode(signatures);

        (nextModule, nextId) = pufferProtocol.getNextValidatorToProvision();

        signatures = _getGuardianSignatures(_getPubKey(bytes32("rocky")));

        // Rocky is now in line
        assertTrue(nextModule == CRAZY_GAINS, "module selection");
        assertTrue(nextId == 0, "module id");
        pufferProtocol.provisionNode(signatures);

        (nextModule, nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextModule == NO_RESTAKING, "module selection");
        assertTrue(nextId == 1, "module id");

        assertEq(
            pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING), 1, "next idx for no restaking module"
        );

        signatures = _getGuardianSignatures(_getPubKey(bytes32("alice")));

        vm.expectEmit(true, true, true, true);
        emit SuccesfullyProvisioned(_getPubKey(bytes32("alice")), 1, NO_RESTAKING);
        pufferProtocol.provisionNode(signatures);
    }

    function testCreatePufferModule() public {
        bytes32 name = bytes32("LEVERAGED_RESTAKING");
        pufferProtocol.createPufferModule(name);
        IPufferModule module = IPufferModule(pufferProtocol.getModuleAddress(name));
        assertEq(module.NAME(), name, "names");
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
        address charlie = makeAddr("charlie");
        vm.deal(charlie, 5 ether);
        vm.deal(address(pool), 100 ether);

        assertEq(pool.balanceOf(address(pufferProtocol)), 0, "0 pufETH in protocol");

        // Create validators
        vm.startPrank(alice);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        vm.startPrank(bob);
        _registerValidatorKey(bytes32("bob"), EIGEN_DA);
        vm.startPrank(charlie);
        _registerValidatorKey(bytes32("charlie"), NO_RESTAKING);

        // PufferProtocol should hold pufETH (bond for 3 validators)
        assertEq(pool.balanceOf(address(pufferProtocol)), 3 ether, "3 pufETH in protocol");

        // Provision validators
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))));
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("bob"))));
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("charlie"))));

        bytes32[] memory aliceProof = fullWithdrawalsMerkleProof.getProof(fullWithdrawalMerkleProofData, 0);

        // Now the node operators submit proofs to get back their bond
        vm.startPrank(alice);
        // Invalid block number = invalid proof
        vm.expectRevert(abi.encodeWithSelector(IPufferProtocol.InvalidMerkleProof.selector));
        pufferProtocol.stopValidator({
            moduleName: NO_RESTAKING,
            validatorIndex: 0,
            blockNumber: 150,
            withdrawalAmount: 32 ether,
            wasSlashed: false,
            merkleProof: aliceProof
        });

        assertEq(pool.balanceOf(alice), 0, "alice has zero pufETH");

        // Valid proof
        pufferProtocol.stopValidator({
            moduleName: NO_RESTAKING,
            validatorIndex: 0,
            blockNumber: 100,
            withdrawalAmount: 32 ether,
            wasSlashed: false,
            merkleProof: aliceProof
        });

        // Try again, now the validator will be in invalid state
        vm.expectRevert(abi.encodeWithSelector(IPufferProtocol.InvalidValidatorState.selector, Status.EXITED));
        pufferProtocol.stopValidator({
            moduleName: NO_RESTAKING,
            validatorIndex: 0,
            blockNumber: 100,
            withdrawalAmount: 32 ether,
            wasSlashed: false,
            merkleProof: aliceProof
        });

        // Alice receives the bond + the reward
        assertEq(pool.balanceOf(alice), 1 ether, "alice received back the bond in pufETH");

        bytes32[] memory bobProof = fullWithdrawalsMerkleProof.getProof(fullWithdrawalMerkleProofData, 1);

        assertEq(pool.balanceOf(bob), 0, "bob has zero pufETH");

        pufferProtocol.stopValidator({
            moduleName: EIGEN_DA,
            validatorIndex: 0,
            blockNumber: 100,
            withdrawalAmount: 31 ether,
            wasSlashed: true,
            merkleProof: bobProof
        });

        assertEq(pool.balanceOf(bob), 0, "bob has zero pufETH after");

        bytes32[] memory charlieProof = fullWithdrawalsMerkleProof.getProof(fullWithdrawalMerkleProofData, 2);

        pufferProtocol.stopValidator({
            moduleName: NO_RESTAKING,
            validatorIndex: 1,
            blockNumber: 100,
            withdrawalAmount: 31.6 ether,
            wasSlashed: false,
            merkleProof: charlieProof
        });

        // assertEq(pool.balanceOf(charlie), 0.6 ether, "Charlie has 0.6 pufETH after");
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

    // Test registering the validator with a huge number of months committed
    function testRegisterValidatorWithHugeCommitment() external {
        bytes memory pubKey = _getPubKey(bytes32("alice"));

        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, NO_RESTAKING);

        // Bond is 2 ether for the mock data
        uint256 bond = 2 ether;

        vm.expectRevert();
        pufferProtocol.registerValidatorKey{ value: bond }(validatorKeyData, NO_RESTAKING, type(uint256).max);
    }

    // Node operator can deposit Bond in pufETH
    function testRegisterValidatorKeyWithPermit() external {
        address alice = makeAddr("alice");
        bytes memory pubKey = _getPubKey(bytes32("alice"));
        vm.deal(alice, 10 ether);

        // Alice mints 2 ETH of pufETH
        vm.startPrank(alice);
        pool.depositETH{ value: 2 ether }();

        // approve pufETH to pufferProtocol
        pool.approve(address(pufferProtocol), type(uint256).max);

        assertEq(pool.balanceOf(address(pufferProtocol)), 0, "zero pufETH before");
        assertEq(pool.balanceOf(alice), 2 ether, "2 pufETH before for alice");

        // In this case, the only important data on permit is the amount
        // Permit call will fail, but the amount is reused
        ValidatorKeyData memory data = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        Permit memory permit;
        permit.amount = pool.balanceOf(alice);

        // Get the smoothing commitment amount for 6 months
        uint256 sc = pufferProtocol.getSmoothingCommitment(6);

        // Register validator key by paying SC in ETH and depositing bond in pufETH
        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, 0, NO_RESTAKING, true);
        pufferProtocol.registerValidatorKeyPermit{ value: sc }(data, NO_RESTAKING, 6, permit);

        assertEq(pool.balanceOf(alice), 0, "0 pufETH after for alice");
        assertEq(pool.balanceOf(address(pufferProtocol)), 2 ether, "2 pufETH after");
    }

    // Node operator can deposit Bond in pufETH with Permit
    function testRegisterValidatorKeyWithPermitSignature() external {
        address alice = makeAddr("alice");
        bytes memory pubKey = _getPubKey(bytes32("alice"));
        vm.deal(alice, 10 ether);

        // Alice mints 2 ETH of pufETH
        vm.startPrank(alice);
        pool.depositETH{ value: 2 ether }();

        assertEq(pool.balanceOf(address(pufferProtocol)), 0, "zero pufETH before");
        assertEq(pool.balanceOf(alice), 2 ether, "2 pufETH before for alice");

        ValidatorKeyData memory data = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        // Generate Permit data for 2 pufETH to the protocol
        Permit memory permit = _signPermit(_testTemps("alice", address(pufferProtocol), 2 ether, block.timestamp));

        // Get the smoothing commitment amount for 6 months
        uint256 sc = pufferProtocol.getSmoothingCommitment(6);

        // Register validator key by paying SC in ETH and depositing bond in pufETH
        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, 0, NO_RESTAKING, true);
        pufferProtocol.registerValidatorKeyPermit{ value: sc }(data, NO_RESTAKING, 6, permit);

        assertEq(pool.balanceOf(alice), 0, "0 pufETH after for alice");
        assertEq(pool.balanceOf(address(pufferProtocol)), 2 ether, "2 pufETH after");
    }

    // Node operator can deposit Bond in pufETH
    function testRegisterValidatorKeyWithPermitSignatureRevertsInvalidSC() external {
        address alice = makeAddr("alice");
        bytes memory pubKey = _getPubKey(bytes32("alice"));
        vm.deal(alice, 10 ether);

        // Alice mints 2 ETH of pufETH
        vm.startPrank(alice);
        pool.depositETH{ value: 2 ether }();

        ValidatorKeyData memory data = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        // Generate Permit data for 10 pufETH to the protocol
        Permit memory permit = _signPermit(_testTemps("alice", address(pufferProtocol), 0.5 ether, block.timestamp));

        // Try to pay invalid SC amount
        vm.expectRevert(IPufferProtocol.InvalidETHAmount.selector);
        pufferProtocol.registerValidatorKeyPermit{ value: 0.1 ether }(data, NO_RESTAKING, 6, permit);

        uint256 sc = pufferProtocol.getSmoothingCommitment(6);

        // Try to pay good amount for SC, but not enough pufETH for the bond
        vm.expectRevert(IPufferProtocol.InvalidETHAmount.selector);
        pufferProtocol.registerValidatorKeyPermit{ value: sc }(data, NO_RESTAKING, 6, permit);
    }

    function testValidatorLimitPerModule() external {
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        vm.expectEmit(true, true, true, true);
        emit IPufferProtocol.ValidatorLimitPerModuleChanged(type(uint128).max, 1);
        pufferProtocol.setValidatorLimitPerModule(NO_RESTAKING, 1);

        // Revert if the registration will be over the limit
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(1);
        bytes memory pubKey = _getPubKey(bytes32("bob"));
        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        uint256 bond = 1 ether;

        vm.expectRevert(IPufferProtocol.ValidatorLimitForModuleReached.selector);
        pufferProtocol.registerValidatorKey{ value: (smoothingCommitment + bond) }(validatorKeyData, NO_RESTAKING, 1);
    }

    function _getGuardianSignatures(bytes memory pubKey) internal view returns (bytes[] memory) {
        (bytes32 moduleName, uint256 pendingIdx) = pufferProtocol.getNextValidatorToProvision();
        Validator memory validator = pufferProtocol.getValidatorInfo(moduleName, pendingIdx);
        // If there is no module return empty byte array
        if (validator.module == address(0)) {
            return new bytes[](0);
        }
        bytes memory withdrawalCredentials = pufferProtocol.getWithdrawalCredentials(validator.module);

        bytes32 digest = LibGuardianMessages._getBeaconDepositMessageToBeSigned(
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

    function _getGuardianSignaturesForSkipping() internal view returns (bytes[] memory) {
        (bytes32 moduleName, uint256 pendingIdx) = pufferProtocol.getNextValidatorToProvision();

        bytes32 digest = LibGuardianMessages._getSkipProvisioningMessage(moduleName, pendingIdx);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardian1SK, digest);
        bytes memory signature1 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        (v, r, s) = vm.sign(guardian2SK, digest);
        bytes memory signature2 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        (v, r, s) = vm.sign(guardian3SK, digest);
        bytes memory signature3 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        bytes[] memory guardianSignatures = new bytes[](3);
        guardianSignatures[0] = signature1;
        guardianSignatures[1] = signature2;
        guardianSignatures[2] = signature3;

        return guardianSignatures;
    }

    // Tests setter for enclave measurements

    function _getMockValidatorKeyData(bytes memory pubKey, bytes32 moduleName)
        internal
        view
        returns (ValidatorKeyData memory)
    {
        bytes[] memory newSetOfPubKeys = new bytes[](3);

        // we have 3 guardians in TestHelper.sol
        newSetOfPubKeys[0] = bytes("key1");
        newSetOfPubKeys[0] = bytes("key2");
        newSetOfPubKeys[0] = bytes("key3");

        address module = pufferProtocol.getModuleAddress(moduleName);

        bytes memory withdrawalCredentials = pufferProtocol.getWithdrawalCredentials(module);

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
            raveEvidence: bytes("mock rave") // Guardians are checking it off chain
         });

        return validatorData;
    }

    function _getPubKey(bytes32 pubKeypart) internal pure returns (bytes memory) {
        return bytes.concat(abi.encodePacked(pubKeypart), bytes16(""));
    }

    // Sets the merkle root and makes sure that the funds get split between WithdrawalPool and PufferPool ASAP
    function _setupMerkleRoot() public {
        // Create EIGEN_DA module
        pufferProtocol.createPufferModule(EIGEN_DA);
        pufferProtocol.setValidatorLimitPerModule(EIGEN_DA, 15);

        // Include the EIGEN_DA in module selection
        bytes32[] memory newWeights = new bytes32[](4);
        newWeights[0] = NO_RESTAKING;
        newWeights[1] = EIGEN_DA;
        newWeights[2] = EIGEN_DA;
        newWeights[3] = CRAZY_GAINS;

        pufferProtocol.setModuleWeights(newWeights);

        address NoRestakingModule = pufferProtocol.getModuleAddress(NO_RESTAKING);
        address eigenDaModule = pufferProtocol.getModuleAddress(EIGEN_DA);

        // Enable PufferProtocol to call `call` function on module
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IPufferModule.call.selector;
        vm.startPrank(_broadcaster);
        accessManager.setTargetFunctionRole(NoRestakingModule, selectors, ROLE_ID_PUFFER_PROTOCOL);
        accessManager.setTargetFunctionRole(eigenDaModule, selectors, ROLE_ID_PUFFER_PROTOCOL);
        vm.stopPrank();

        // We are simulating 3 full withdrawals
        // 2 are from NoRestakingModule and 1 from eigenDaModule
        address[] memory modules = new address[](2);
        modules[0] = NoRestakingModule;
        modules[1] = eigenDaModule;

        // Give funds to modules
        vm.deal(modules[0], 200 ether);
        vm.deal(modules[1], 100 ether);

        // Amounts of full withdrawals that we want to move from modules to pools
        uint256[] memory amounts = new uint256[](2);
        // For no restaking module
        // Assume that the first withdrawal is over 32 ETH, but the guardians will we cap it to 32 ETH, the rest stays in module for rewards withdrawal
        // The second withdrawal is 3.16 (inactiviy leak)
        amounts[0] = 32 ether + 31.6 ether;
        amounts[1] = 31 ether; // got slashed

        MerkleProofData[] memory validatorExits = new MerkleProofData[](3);
        validatorExits[0] = MerkleProofData({ moduleName: NO_RESTAKING, index: 0, amount: 32 ether, wasSlashed: 0 });
        validatorExits[1] = MerkleProofData({ moduleName: EIGEN_DA, index: 0, amount: 31 ether, wasSlashed: 1 });
        validatorExits[2] = MerkleProofData({ moduleName: NO_RESTAKING, index: 1, amount: 31.6 ether, wasSlashed: 0 });
        bytes32 merkleRoot = _buildMerkleProof(validatorExits);

        // Assert starting state of the pools
        assertEq(address(pool).balance, 0, "starting pool balance");
        assertEq(address(withdrawalPool).balance, 0, "starting withdraawal pool balance");

        bytes[] memory signatures = _getGuardianEOASignatures(
            LibGuardianMessages._getPostFullWithdrawalsRootMessage(merkleRoot, 100, modules, amounts)
        );

        // modules.length and amounts.length don't match
        vm.expectRevert(IPufferProtocol.InvalidData.selector);
        pufferProtocol.postFullWithdrawalsRoot({
            root: merkleRoot,
            blockNumber: 100,
            modules: new address[](5), // lengths don't match
            amounts: amounts,
            guardianSignatures: signatures
        });

        // Submit a valid proof
        pufferProtocol.postFullWithdrawalsRoot({
            root: merkleRoot,
            blockNumber: 100,
            modules: modules,
            amounts: amounts,
            guardianSignatures: signatures
        });

        // Total withdrawal eth is 32 + 31 + 31.6 = 94.6
        // 0.14 stays in protocol because the first amount is over 32 eth (it has the rewards in it)

        // 94.6 goes to the pools
        // Default split rate for withdrawal pool is 10%
        assertEq(address(withdrawalPool).balance, 9.46 ether, "ending withdraawal pool balance");
        assertEq(address(pool).balance, 85.14 ether, "ending pool balance");
    }

    function _buildMerkleProof(MerkleProofData[] memory validatorExits) internal returns (bytes32 root) {
        fullWithdrawalsMerkleProof = new Merkle();

        fullWithdrawalMerkleProofData = new bytes32[](validatorExits.length);

        for (uint256 i = 0; i < validatorExits.length; ++i) {
            MerkleProofData memory validatorData = validatorExits[i];
            fullWithdrawalMerkleProofData[i] = keccak256(
                bytes.concat(
                    keccak256(
                        abi.encode(
                            validatorData.moduleName,
                            validatorData.index,
                            validatorData.amount,
                            validatorData.wasSlashed
                        )
                    )
                )
            );
        }

        root = fullWithdrawalsMerkleProof.getRoot(fullWithdrawalMerkleProofData);
    }
}

struct MerkleProofData {
    bytes32 moduleName;
    uint256 index;
    uint256 amount;
    uint8 wasSlashed;
}
