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
import { IPufferOracle } from "pufETH/interface/IPufferOracle.sol";
import { ROLE_ID_PUFFER_PROTOCOL, ROLE_ID_DAO } from "pufETHScript/Roles.sol";
import { Unauthorized } from "puffer/Errors.sol";
import { LibGuardianMessages } from "puffer/LibGuardianMessages.sol";
import { Permit } from "puffer/struct/Permit.sol";
import { Merkle } from "murky/Merkle.sol";
import { console } from "forge-std/console.sol";

contract PufferProtocolTest is TestHelper {
    using ECDSA for bytes32;

    Merkle fullWithdrawalsMerkleProof;
    bytes32[] fullWithdrawalMerkleProofData;

    event ValidatorKeyRegistered(bytes indexed pubKey, uint256 indexed, bytes32 indexed, bool);
    event SuccessfullyProvisioned(bytes indexed pubKey, uint256 indexed, bytes32 indexed);
    event ValidatorDequeued(bytes indexed pubKey, uint256 validatorIndex);
    event ModuleWeightsChanged(bytes32[] oldWeights, bytes32[] newWeights);

    bytes zeroPubKey = new bytes(48);
    bytes32 zeroPubKeyPart;

    bytes32 constant EIGEN_DA = bytes32("EIGEN_DA");
    bytes32 constant CRAZY_GAINS = bytes32("CRAZY_GAINS");

    Permit emptyPermit;

    // 0.01 %
    uint256 pointZeroZeroOne = 0.0001e18;
    // 0.02 %
    uint256 pointZeroZeroTwo = 0.0002e18;
    // 0.05 %
    uint256 pointZeroFive = 0.0005e18;
    // 0.1% diff
    uint256 pointZeroOne = 0.001e18;

    address alice = makeAddr("alice");

    function setUp() public override {
        super.setUp();

        vm.deal(address(this), 1000 ether);

        // Setup roles
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = PufferProtocol.createPufferModule.selector;
        selectors[1] = PufferProtocol.setModuleWeights.selector;
        selectors[2] = bytes4(hex"4f1ef286"); // signature for UUPS.upgradeToAndCall(address newImplementation, bytes memory data)

        // For simplicity grant DAO role to this contract
        vm.startPrank(_broadcaster);
        accessManager.setTargetFunctionRole(address(pufferProtocol), selectors, ROLE_ID_DAO);
        accessManager.grantRole(ROLE_ID_DAO, address(this), 0);
        vm.stopPrank();

        // Set daily withdrawals limit
        vm.prank(OPERATIONS_MULTISIG);
        pufferVault.setDailyWithdrawalLimit(1000 ether);

        _skipDefaultFuzzAddresses();

        fuzzedAddressMapping[address(pufferProtocol)] = true;
    }

    // Setup
    function test_setup() public {
        assertTrue(address(pufferProtocol.PUFFER_VAULT()) != address(0), "puffer vault address");
        address module = pufferProtocol.getModuleAddress(NO_RESTAKING);
        assertEq(PufferModule(payable(module)).NAME(), NO_RESTAKING, "bad name");
    }

    function test_register_validator_key() public {
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
    }

    function test_empty_queue() public {
        (bytes32 moduleName, uint256 idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(moduleName, bytes32("NO_VALIDATORS"), "name");
        assertEq(idx, type(uint256).max, "name");
    }

    // Test Skipping the validator
    function test_skip_provisioning() public {
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("bob"), NO_RESTAKING);

        (bytes32 moduleName, uint256 idx) = pufferProtocol.getNextValidatorToProvision();
        uint256 moduleSelectionIndex = pufferProtocol.getModuleSelectIndex();

        assertEq(moduleName, NO_RESTAKING, "module");
        assertEq(idx, 0, "idx");
        assertEq(moduleSelectionIndex, 0, "module selection idx");

        assertTrue(pufferVault.balanceOf(address(this)) == 0, "zero pufETH");

        pufferProtocol.skipProvisioning(NO_RESTAKING, _getGuardianSignaturesForSkipping());

        // This contract should receive pufETH because of the skipProvisioning
        assertTrue(pufferVault.balanceOf(address(this)) != 0, "non zero pufETH");

        Validator memory aliceValidator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 0);
        assertTrue(aliceValidator.status == Status.SKIPPED, "did not update status");

        (moduleName, idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(moduleName, NO_RESTAKING, "module");
        assertEq(idx, 1, "idx should be 1");

        bytes[] memory signatures = _getGuardianSignatures(_getPubKey(bytes32("bob")));

        vm.expectEmit(true, true, true, true);
        emit SuccessfullyProvisioned(_getPubKey(bytes32("bob")), 1, NO_RESTAKING);
        pufferProtocol.provisionNode(signatures, 0);
        moduleSelectionIndex = pufferProtocol.getModuleSelectIndex();
        assertEq(moduleSelectionIndex, 1, "module idx changed");
    }

    // Create an existing module should revert
    function test_create_existing_module_fails() public {
        vm.startPrank(DAO);
        vm.expectRevert(IPufferProtocol.ModuleAlreadyExists.selector);
        pufferProtocol.createPufferModule(NO_RESTAKING, "", address(0));
    }

    // Invalid pub key shares length
    function test_register_invalid_pubkey_shares_length() public {
        ValidatorKeyData memory data = _getMockValidatorKeyData(new bytes(48), NO_RESTAKING);
        data.blsPubKeySet = new bytes(22);

        Permit memory permit;

        vm.expectRevert(IPufferProtocol.InvalidBLSPublicKeySet.selector);
        pufferProtocol.registerValidatorKey{ value: 4 ether }(data, NO_RESTAKING, 30, emptyPermit, emptyPermit);
    }

    // Invalid private key shares length
    function test_register_invalid_privKey_shares() public {
        ValidatorKeyData memory data = _getMockValidatorKeyData(new bytes(48), NO_RESTAKING);
        data.blsEncryptedPrivKeyShares = new bytes[](2);

        vm.expectRevert(IPufferProtocol.InvalidBLSPrivateKeyShares.selector);
        pufferProtocol.registerValidatorKey{ value: 4 ether }(data, NO_RESTAKING, 30, emptyPermit, emptyPermit);
    }

    // Try registering with invalid module
    function test_register_to_invalid_module() public {
        uint256 smoothingCommitment = pufferOracle.getValidatorTicketPrice() * 30;
        bytes memory pubKey = _getPubKey(bytes32("charlie"));
        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        vm.expectRevert(IPufferProtocol.ValidatorLimitForModuleReached.selector);
        pufferProtocol.registerValidatorKey{ value: smoothingCommitment }(
            validatorKeyData, bytes32("imaginary module"), 30, emptyPermit, emptyPermit
        );
    }

    // Try registering with invalid amount paid
    function test_register_with_invalid_amount_paid() public {
        bytes memory pubKey = _getPubKey(bytes32("charlie"));
        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        vm.expectRevert(IPufferProtocol.InvalidETHAmount.selector);
        pufferProtocol.registerValidatorKey{ value: 5 ether }(
            validatorKeyData, NO_RESTAKING, 30, emptyPermit, emptyPermit
        );
    }

    function test_module_DOS() external {
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
        // pufferProtocol.cancelRegistration(NO_RESTAKING, 0);
        pufferProtocol.cancelRegistration(NO_RESTAKING, 1);
        pufferProtocol.cancelRegistration(NO_RESTAKING, 2);
        pufferProtocol.cancelRegistration(NO_RESTAKING, 3);
        pufferProtocol.cancelRegistration(NO_RESTAKING, 4);
        // Skip 5, we want to provision 5
        pufferProtocol.cancelRegistration(NO_RESTAKING, 6);
        pufferProtocol.cancelRegistration(NO_RESTAKING, 7);

        (bytes32 module, uint256 idx) = pufferProtocol.getNextValidatorToProvision();
        assertEq(module, NO_RESTAKING, "module");
        assertEq(idx, 0, "idx");

        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))), 0);

        uint256 next = pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING);
        assertEq(next, 1, "next idx");

        (module, idx) = pufferProtocol.getNextValidatorToProvision();
        assertEq(module, NO_RESTAKING, "module");
        assertEq(idx, 5, "idx");

        // Provision node updates the idx to current + 1
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("ford"))), 0);

        // That idx is 6
        next = pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING);
        assertEq(next, 6, "next idx");

        // From there the counter of '5' starts before we return nothing to provision
        (module, idx) = pufferProtocol.getNextValidatorToProvision();
        assertEq(module, NO_RESTAKING, "module");
        assertEq(idx, 8, "idx");
    }

    // Try updating for future block
    function test_proof_of_reserve() external {
        vm.roll(50401);

        pufferOracle.proofOfReserve({
            newLockedETH: 32 ether,
            blockNumber: 50401,
            numberOfActivePufferValidators: 10,
            totalNumberOfValidators: 1000,
            guardianSignatures: _getGuardianEOASignatures(
                LibGuardianMessages._getProofOfReserveMessage({
                    lockedETH: 32 ether,
                    blockNumber: 50401,
                    numberOfActivePufferValidators: 10,
                    totalNumberOfValidators: 1000
                })
                )
        });

        bytes[] memory signatures2 = _getGuardianEOASignatures(
            LibGuardianMessages._getProofOfReserveMessage({
                lockedETH: 0,
                blockNumber: 50401,
                numberOfActivePufferValidators: 10,
                totalNumberOfValidators: 1000
            })
        );

        // Second update should revert as it has not passed enough time between two updates
        vm.expectRevert(IPufferOracle.OutsideUpdateWindow.selector);
        pufferOracle.proofOfReserve({
            newLockedETH: 0,
            blockNumber: 50401,
            numberOfActivePufferValidators: 10,
            totalNumberOfValidators: 1000,
            guardianSignatures: signatures2
        });
    }

    function test_burst_threshold() external {
        vm.roll(50401);

        // Update the reserves and make it so that the next validator is over threshold
        pufferOracle.proofOfReserve({
            newLockedETH: 32 ether,
            blockNumber: 50401,
            numberOfActivePufferValidators: 10,
            totalNumberOfValidators: 10,
            guardianSignatures: _getGuardianEOASignatures(
                LibGuardianMessages._getProofOfReserveMessage({
                    lockedETH: 32 ether,
                    blockNumber: 50401,
                    numberOfActivePufferValidators: 10,
                    totalNumberOfValidators: 10
                })
                )
        });

        uint256 sc = pufferOracle.getValidatorTicketPrice() * 30;

        uint256 balanceBefore = address(validatorTicket).balance;

        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        uint256 balanceAfter = address(validatorTicket).balance;

        assertEq(balanceAfter, balanceBefore + sc, "treasury gets everything");
    }

    // Set validator limit and try registering that many validators
    function test_fuzz_register_many_validators(uint8 numberOfValidatorsToProvision) external {
        for (uint256 i = 0; i < uint256(numberOfValidatorsToProvision); ++i) {
            vm.deal(address(this), 2 ether);
            _registerValidatorKey(bytes32(i), NO_RESTAKING);
        }
    }

    // Try registering without RAVE evidence
    function test_register_no_sgx() public {
        uint256 vtPrice = pufferOracle.getValidatorTicketPrice() * 30;

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

        pufferProtocol.registerValidatorKey{ value: vtPrice + 2 ether }(
            validatorData, NO_RESTAKING, 30, emptyPermit, emptyPermit
        );
    }

    // Try registering with invalid BLS key length
    function test_register_invalid_bls_key() public {
        uint256 smoothingCommitment = pufferOracle.getValidatorTicketPrice();

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
        pufferProtocol.registerValidatorKey{ value: smoothingCommitment }(
            validatorData, NO_RESTAKING, 30, emptyPermit, emptyPermit
        );
    }

    function test_get_payload() public {
        (bytes[] memory guardianPubKeys, bytes memory withdrawalCredentials, uint256 threshold, uint256 ethAmount) =
            pufferProtocol.getPayload(NO_RESTAKING, false, 30);

        assertEq(guardianPubKeys[0], guardian1EnclavePubKey, "guardian1");
        assertEq(guardianPubKeys[1], guardian2EnclavePubKey, "guardian2");
        assertEq(guardianPubKeys[2], guardian3EnclavePubKey, "guardian3");

        assertEq(guardianPubKeys.length, 3, "pubkeys len");
        assertEq(threshold, 1, "threshold");
    }

    // Try to provision a validator when there is nothing to provision
    function test_provision_reverts() public {
        (bytes32 moduleName, uint256 idx) = pufferProtocol.getNextValidatorToProvision();
        assertEq(type(uint256).max, idx, "module");

        bytes[] memory signatures =
            _getGuardianSignatures(hex"0000000000000000000000000000000000000000000000000000000000000000");

        vm.expectRevert();
        pufferProtocol.provisionNode(signatures, 0);
    }

    // function testSetProtocolFeeRate() public {
    //     uint256 rate = 10 * FixedPointMathLib.WAD;
    //     pufferProtocol.setProtocolFeeRate(rate); // 10%
    //     assertEq(pufferProtocol.getProtocolFeeRate(), rate, "new rate");
    // }

    // function testSetGuardiansFeeRateOverTheLimit() public {
    //     uint256 rate = 30 * FixedPointMathLib.WAD;
    //     vm.expectRevert(IPufferProtocol.InvalidData.selector);
    //     pufferProtocol.setGuardiansFeeRate(rate);
    // }

    // function testSetProtocolFeeRateOverTheLimit() public {
    //     uint256 rate = 30 * FixedPointMathLib.WAD;
    //     vm.expectRevert(IPufferProtocol.InvalidData.selector);
    //     pufferProtocol.setProtocolFeeRate(rate);
    // }

    function test_fee_calculations() public {
        // // Default values are
        // // 2% guardians
        // // 10% withdrawal fee pool
        // // 0.5% guardians
        // // rest to the PufferPool
        // uint256 amount = pufferOracle.getValidatorTicketPrice();

        // assertEq(0, pufferProtocol.TREASURY().balance, "zero treasury");
        // assertEq(0, address(pufferProtocol.GUARDIAN_MODULE()).balance, "zero guardians");
        // assertEq(1000 ether, address(pufferProtocol.PUFFER_VAULT()).balance, "starting vault balance");

        // // We don't have additional validations on if the validator is active or not
        // // pufferProtocol.extendCommitment{ value: amount }(NO_RESTAKING, 0, 12);

        // assertEq(2280296714778796, pufferProtocol.TREASURY().balance, "non zero treasury");
        // assertEq(570074178694699, address(pufferProtocol.GUARDIAN_MODULE()).balance, "non zero guardians");
        // assertEq(100048018360919684, address(pufferProtocol.PUFFER_VAULT()).balance, "non zero pool");
    }

    function test_change_module() public {
        vm.expectRevert(IPufferProtocol.InvalidPufferModule.selector);
        pufferProtocol.changeModule(NO_RESTAKING, PufferModule(payable(address(5))));
    }

    function test_change_module_to_custom_module() public {
        pufferProtocol.changeModule(bytes32("RANDOM_MODULE"), PufferModule(payable(address(5))));
        address moduleAfterChange = pufferProtocol.getModuleAddress("RANDOM_MODULE");
        assertTrue(address(0) != moduleAfterChange, "module did not change");
    }

    // function testRegisterOneValidator() public {
    //     // Start balance of the PufferVault
    //     uint256 startBalance = 1000 ether;

    //     assertEq(pufferVault.totalAssets(), startBalance, "it should start with 1000 eth");
    //     assertEq(pufferVault.balanceOf(LIQUIDITY_PROVIDER), startBalance, "the LP got all the pufETH");
    //     assertEq(pufferVault.maxWithdraw(LIQUIDITY_PROVIDER), startBalance, "lp can withdraw everything");

    //     // Register 1 validator
    //     _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

    //     uint256 smoothingCommitment = pufferOracle.getValidatorTicketPrice();
    //     uint256 bond = 1 ether;

    //     uint256 treasuryFee =
    //         FixedPointMathLib.fullMulDiv(smoothingCommitment, pufferProtocol.getProtocolFeeRate(), 100 * 1e18);
    //     uint256 guardiansFee =
    //         FixedPointMathLib.fullMulDiv(smoothingCommitment, pufferProtocol.getGuardiansFeeRate(), 100 * 1e18);

    //     // Amount of rewards for pufETH holders (SC - fees)
    //     assertEq(smoothingCommitment - treasuryFee - guardiansFee, 116960846822092934, "rewards"); // ~0.11 ETH

    //     uint256 expectedAmount = startBalance + smoothingCommitment + bond - treasuryFee - guardiansFee;
    //     assertEq(pufferVault.totalAssets(), expectedAmount, "vault balance after deposit");

    //     assertEq(pufferVault.balanceOf(address(pufferProtocol)), 1 ether, "protocol should have 1 pufETH");

    //     assertGt(
    //         pufferVault.maxWithdraw(LIQUIDITY_PROVIDER),
    //         startBalance,
    //         "lp can withdraw more than it originally deposited"
    //     );

    //     assertGt(pufferVault.maxWithdraw(address(pufferProtocol)), 1 ether, "pufETH in protocol appreciated");

    //     vm.startPrank(LIQUIDITY_PROVIDER);
    //     uint256 ethWithdrawn = pufferVault.withdraw(
    //         pufferVault.maxWithdraw(address(LIQUIDITY_PROVIDER)), LIQUIDITY_PROVIDER, LIQUIDITY_PROVIDER
    //     );

    //     vm.startPrank(address(pufferProtocol));
    //     pufferVault.withdraw(
    //         pufferVault.maxWithdraw(address(pufferProtocol)), makeAddr("puffer_recipient"), address(pufferProtocol)
    //     );

    //     // 1 wei is left because of rounding
    //     assertEq(pufferVault.totalAssets(), 1, "everything is gone");
    // }

    function test_stop_registration() public {
        // Register two validators
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("bob"), NO_RESTAKING);

        assertApproxEqRel(
            pufferVault.maxWithdraw(address(pufferProtocol)),
            2 ether,
            pointZeroOne,
            "pool should have the bond amount for 2 validators"
        );

        vm.prank(address(4123123)); // random sender
        vm.expectRevert(Unauthorized.selector);
        pufferProtocol.cancelRegistration(NO_RESTAKING, 0);

        (bytes32 moduleName, uint256 idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(moduleName, NO_RESTAKING, "module");
        assertEq(0, idx, "module");
        assertEq(pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING), 0, "zero index is next in line");

        bytes memory alicePubKey = _getPubKey(bytes32("alice"));

        vm.expectEmit(true, true, true, true);
        emit ValidatorDequeued(alicePubKey, 0);
        pufferProtocol.cancelRegistration(NO_RESTAKING, 0);

        assertEq(pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING), 1, "1 index is next in line");

        assertApproxEqRel(
            pufferVault.maxWithdraw(address(pufferProtocol)),
            1 ether,
            pointZeroOne,
            "pool should have the bond amount for 1 validators"
        );
        // Because this contract is msg.sender, it means that it is the node operator
        assertApproxEqRel(
            pufferVault.maxWithdraw(address(this)),
            1 ether,
            pointZeroOne,
            "node operator should get ~1 pufETH for Alice"
        );

        (moduleName, idx) = pufferProtocol.getNextValidatorToProvision();

        assertEq(moduleName, NO_RESTAKING, "module after");
        assertEq(1, idx, "module after");

        bytes[] memory signatures = _getGuardianSignatures(alicePubKey);

        // Unauthorized, because the protocol is expecting signature for bob
        vm.expectRevert(Unauthorized.selector);
        pufferProtocol.provisionNode(signatures, 0);

        // Bob should be provisioned next
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("bob"))), 0);

        // Invalid status
        vm.expectRevert(abi.encodeWithSelector(IPufferProtocol.InvalidValidatorState.selector, Status.DEQUEUED));
        pufferProtocol.cancelRegistration(NO_RESTAKING, 0);
    }

    function test_register_multiple_validator_keys_and_dequeue(bytes32 alicePubKeyPart, bytes32 bobPubKeyPart) public {
        address bob = makeAddr("bob");
        vm.deal(bob, 10 ether);

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

        bytes[] memory signatures = _getGuardianSignatures(zeroPubKey);

        // // 1. provision zero key
        vm.expectEmit(true, true, true, true);
        emit SuccessfullyProvisioned(zeroPubKey, 0, NO_RESTAKING);
        pufferProtocol.provisionNode(signatures, 0);

        bytes[] memory bobSignatures = _getGuardianSignatures(bobPubKey);

        // Provision Bob that is not zero pubKey
        vm.expectEmit(true, true, true, true);
        emit SuccessfullyProvisioned(bobPubKey, 1, NO_RESTAKING);
        pufferProtocol.provisionNode(bobSignatures, 0);

        Validator memory bobValidator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 1);

        assertTrue(bobValidator.status == Status.ACTIVE, "bob should be active");

        pufferProtocol.skipProvisioning(NO_RESTAKING, _getGuardianSignaturesForSkipping());

        signatures = _getGuardianSignatures(zeroPubKey);

        emit SuccessfullyProvisioned(zeroPubKey, 3, NO_RESTAKING);
        pufferProtocol.provisionNode(signatures, 0);

        // Get validators
        Validator[] memory registeredValidators = pufferProtocol.getValidators(NO_RESTAKING);
        assertEq(registeredValidators.length, 5, "5 registered validators");
        assertEq(registeredValidators[0].node, address(this), "this contract should be the first one");
        assertEq(registeredValidators[1].node, bob, "bob should be the second one");
        assertEq(registeredValidators[2].node, alice, "alice should be the third one");
        assertEq(registeredValidators[3].node, address(this), "this contract should should be the fourth one");
        assertEq(registeredValidators[4].node, address(this), "this contract should should be the fifth one");
    }

    function test_provision_node() public {
        pufferProtocol.createPufferModule(EIGEN_DA, "", address(0));
        pufferProtocol.createPufferModule(CRAZY_GAINS, "", address(0));

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

        vm.deal(address(pufferVault), 10000 ether);

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
        emit SuccessfullyProvisioned(_getPubKey(bytes32("bob")), 0, NO_RESTAKING);
        pufferProtocol.provisionNode(signatures, 0);

        (nextModule, nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextModule == EIGEN_DA, "module selection");
        // Id is zero, because that is the first in this queue
        assertTrue(nextId == 0, "module id");

        signatures = _getGuardianSignatures(_getPubKey(bytes32("benjamin")));

        vm.expectEmit(true, true, true, true);
        emit SuccessfullyProvisioned(_getPubKey(bytes32("benjamin")), 0, EIGEN_DA);
        pufferProtocol.provisionNode(signatures, 0);

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
        pufferProtocol.provisionNode(signatures, 0);

        signatures = _getGuardianSignatures(_getPubKey(bytes32("jason")));

        // Provision Jason
        pufferProtocol.provisionNode(signatures, 0);

        (nextModule, nextId) = pufferProtocol.getNextValidatorToProvision();

        signatures = _getGuardianSignatures(_getPubKey(bytes32("rocky")));

        // Rocky is now in line
        assertTrue(nextModule == CRAZY_GAINS, "module selection");
        assertTrue(nextId == 0, "module id");
        pufferProtocol.provisionNode(signatures, 0);

        (nextModule, nextId) = pufferProtocol.getNextValidatorToProvision();

        assertTrue(nextModule == NO_RESTAKING, "module selection");
        assertTrue(nextId == 1, "module id");

        assertEq(
            pufferProtocol.getNextValidatorToBeProvisionedIndex(NO_RESTAKING), 1, "next idx for no restaking module"
        );

        signatures = _getGuardianSignatures(_getPubKey(bytes32("alice")));

        vm.expectEmit(true, true, true, true);
        emit SuccessfullyProvisioned(_getPubKey(bytes32("alice")), 1, NO_RESTAKING);
        pufferProtocol.provisionNode(signatures, 0);
    }

    function test_create_puffer_module() public {
        bytes32 name = bytes32("LEVERAGED_RESTAKING");
        pufferProtocol.createPufferModule(name, "", address(0));
        IPufferModule module = IPufferModule(pufferProtocol.getModuleAddress(name));
        assertEq(module.NAME(), name, "names");
    }

    function test_claim_bond() public {
        // In our test case, we are posting roots and simulating a full withdrawal before the validator registration
        _setupMerkleRoot();

        // For us to test the withdrawal from the node operator, we must register and provision that validator
        // In our case we have 2 validators NO_RESTAKING and EIGEN_DA

        vm.deal(alice, 5 ether);
        address bob = makeAddr("bob");
        vm.deal(bob, 5 ether);
        address charlie = makeAddr("charlie");
        vm.deal(charlie, 5 ether);
        vm.deal(address(pufferVault), 100 ether);

        assertEq(pufferVault.balanceOf(address(pufferProtocol)), 0, "0 pufETH in protocol");

        // Create validators
        vm.startPrank(alice);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        vm.startPrank(bob);
        _registerValidatorKey(bytes32("bob"), EIGEN_DA);
        vm.startPrank(charlie);
        _registerValidatorKey(bytes32("charlie"), NO_RESTAKING);

        // PufferProtocol should hold pufETH (bond for 3 validators)
        assertGt(
            (pufferVault.maxWithdraw(address(pufferProtocol))), 3 ether, "> 3 worth of ETH in pufETH in the protocol"
        );

        // Provision validators
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))), 0);
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("bob"))), 0);
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("charlie"))), 0);

        bytes32[] memory aliceProof = fullWithdrawalsMerkleProof.getProof(fullWithdrawalMerkleProofData, 0);

        // Now the node operators submit proofs to get back their bond
        vm.startPrank(alice);
        // Invalid block number = invalid proof
        vm.expectRevert(abi.encodeWithSelector(IPufferProtocol.InvalidMerkleProof.selector));
        pufferProtocol.retrieveBond({
            moduleName: NO_RESTAKING,
            validatorIndex: 0,
            blockNumber: 150,
            withdrawalAmount: 32 ether,
            wasSlashed: false,
            validatorStopTimestamp: block.timestamp,
            merkleProof: aliceProof
        });

        assertEq(pufferVault.balanceOf(alice), 0, "alice has zero pufETH");

        // Valid proof
        pufferProtocol.retrieveBond({
            moduleName: NO_RESTAKING,
            validatorIndex: 0,
            blockNumber: 100,
            withdrawalAmount: 32 ether,
            wasSlashed: false,
            validatorStopTimestamp: block.timestamp,
            merkleProof: aliceProof
        });

        // Try again, now the validator will be in invalid state
        vm.expectRevert(abi.encodeWithSelector(IPufferProtocol.InvalidValidatorState.selector, Status.EXITED));
        pufferProtocol.retrieveBond({
            moduleName: NO_RESTAKING,
            validatorIndex: 0,
            blockNumber: 100,
            withdrawalAmount: 32 ether,
            wasSlashed: false,
            validatorStopTimestamp: block.timestamp,
            merkleProof: aliceProof
        });

        // Alice receives the bond + the reward
        assertGt(
            pufferVault.maxWithdraw(alice),
            1 ether,
            "alice received back the bond in pufETH which is worth more than she deposited"
        );

        bytes32[] memory bobProof = fullWithdrawalsMerkleProof.getProof(fullWithdrawalMerkleProofData, 1);

        assertEq(pufferVault.balanceOf(bob), 0, "bob has zero pufETH");

        pufferProtocol.retrieveBond({
            moduleName: EIGEN_DA,
            validatorIndex: 0,
            blockNumber: 100,
            withdrawalAmount: 31 ether,
            wasSlashed: true,
            validatorStopTimestamp: block.timestamp,
            merkleProof: bobProof
        });

        assertEq(pufferVault.balanceOf(bob), 0, "bob has zero pufETH after");

        bytes32[] memory charlieProof = fullWithdrawalsMerkleProof.getProof(fullWithdrawalMerkleProofData, 2);

        pufferProtocol.retrieveBond({
            moduleName: NO_RESTAKING,
            validatorIndex: 1,
            blockNumber: 100,
            withdrawalAmount: 31.6 ether,
            wasSlashed: false,
            validatorStopTimestamp: block.timestamp,
            merkleProof: charlieProof
        });

        assertGt(pufferVault.maxWithdraw(charlie), 0.6 ether, "Charlie has 0.6 + extra that he earned after");
    }

    // Test smart contract upgradeability (UUPS)
    function test_upgrade() public {
        vm.expectRevert();
        uint256 result = PufferProtocolMockUpgrade(payable(address(pufferVault))).returnSomething();

        PufferProtocolMockUpgrade newImplementation = new PufferProtocolMockUpgrade(address(beacon));
        pufferProtocol.upgradeToAndCall(address(newImplementation), "");

        result = PufferProtocolMockUpgrade(payable(address(pufferProtocol))).returnSomething();

        assertEq(result, 1337);
    }

    // Test registering the validator with a huge number of months committed
    function test_register_validator_with_huge_commitment() external {
        bytes memory pubKey = _getPubKey(bytes32("alice"));

        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, NO_RESTAKING);

        // Bond is 2 ether for the mock data
        uint256 bond = 2 ether;

        vm.expectRevert();
        pufferProtocol.registerValidatorKey{ value: bond }(
            validatorKeyData, NO_RESTAKING, type(uint256).max, emptyPermit, emptyPermit
        );
    }

    // Node operator can deposit Bond in pufETH
    function test_register_pufETH_approve_buy_VT() external {
        bytes memory pubKey = _getPubKey(bytes32("alice"));
        vm.deal(alice, 10 ether);

        uint256 expectedMint = pufferVault.previewDeposit(1 ether);
        assertGt(expectedMint, 0, "should expect more pufETH");

        // Alice mints 2 ETH of pufETH
        vm.startPrank(alice);
        uint256 minted = pufferVault.depositETH{ value: 1 ether }(alice);
        assertGt(minted, 0, "should mint pufETH");

        // approve pufETH to pufferProtocol
        pufferVault.approve(address(pufferProtocol), type(uint256).max);

        assertEq(pufferVault.balanceOf(address(pufferProtocol)), 0, "zero pufETH before");
        assertEq(pufferVault.balanceOf(alice), 1 ether, "1 pufETH before for alice");

        // In this case, the only important data on permit is the amount
        // Permit call will fail, but the amount is reused
        ValidatorKeyData memory data = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        Permit memory permit;
        permit.amount = pufferVault.balanceOf(alice);

        // Get the smoothing commitment amount for 180 days
        uint256 sc = pufferOracle.getValidatorTicketPrice() * 180;

        // Register validator key by paying SC in ETH and depositing bond in pufETH
        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, 0, NO_RESTAKING, true);
        pufferProtocol.registerValidatorKey{ value: sc }(data, NO_RESTAKING, 180, permit, emptyPermit);

        assertEq(pufferVault.balanceOf(alice), 0, "0 pufETH after for alice");
        assertApproxEqRel(pufferVault.balanceOf(address(pufferProtocol)), 1 ether, pointZeroZeroTwo, "~1 pufETH after");
    }

    // Node operator can deposit Bond with Permit and pay for the VT in ETH
    function test_register_pufETH_permit_pay_VT() external {
        bytes memory pubKey = _getPubKey(bytes32("alice"));
        vm.deal(alice, 10 ether);

        // Alice mints 2 ETH of pufETH
        vm.startPrank(alice);
        pufferVault.depositETH{ value: 1 ether }(alice);

        assertEq(pufferVault.balanceOf(address(pufferProtocol)), 0, "zero pufETH before");
        assertEq(pufferVault.balanceOf(alice), 1 ether, "1 pufETH before for alice");

        ValidatorKeyData memory data = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        // Generate Permit data for 2 pufETH to the protocol
        Permit memory permit = _signPermit(
            _testTemps("alice", address(pufferProtocol), 2 ether, block.timestamp), pufferVault.DOMAIN_SEPARATOR()
        );

        uint256 numberOfDays = 180;
        // Get the smoothing commitment amount for 6 months
        uint256 sc = pufferOracle.getValidatorTicketPrice() * numberOfDays;

        // Register validator key by paying SC in ETH and depositing bond in pufETH
        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, 0, NO_RESTAKING, true);
        pufferProtocol.registerValidatorKey{ value: sc }(data, NO_RESTAKING, numberOfDays, permit, emptyPermit);

        assertEq(pufferVault.balanceOf(alice), 0, "0 pufETH after for alice");
        assertEq(pufferVault.balanceOf(address(pufferProtocol)), 1 ether, "1 pufETH after");
    }

    // Node operator can deposit both VT and pufETH with Permit
    function test_register_both_permit() external {
        bytes memory pubKey = _getPubKey(bytes32("alice"));
        vm.deal(alice, 10 ether);

        uint256 numberOfDays = 200;
        uint256 amount = pufferOracle.getValidatorTicketPrice() * numberOfDays;

        // Alice mints 2 ETH of pufETH
        vm.startPrank(alice);
        // Purchase pufETH
        pufferVault.depositETH{ value: 1 ether }(alice);
        // Alice purchases VT
        validatorTicket.purchaseValidatorTicket{ value: amount }(alice);

        // Because Alice purchased a lot of VT's, it changed the conversion rate
        // Because of that the registerValidatorKey will .transferFrom a smaller amount of pufETH
        uint256 leftOverPufETH = pufferVault.balanceOf(alice) - pufferVault.convertToShares(1 ether);

        assertEq(pufferVault.balanceOf(address(pufferProtocol)), 0, "zero pufETH before");
        assertEq(pufferVault.balanceOf(alice), 1 ether, "1 pufETH before for alice");
        assertEq(validatorTicket.balanceOf(alice), _upscaleTo18Decimals(numberOfDays), "VT before for alice");

        ValidatorKeyData memory data = _getMockValidatorKeyData(pubKey, NO_RESTAKING);

        uint256 bond = 1 ether;
        Permit memory pufETHPermit = _signPermit(
            _testTemps("alice", address(pufferProtocol), bond, block.timestamp), pufferVault.DOMAIN_SEPARATOR()
        );
        Permit memory vtPermit = _signPermit(
            _testTemps("alice", address(pufferProtocol), _upscaleTo18Decimals(amount), block.timestamp),
            validatorTicket.DOMAIN_SEPARATOR()
        );

        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, 0, NO_RESTAKING, true);
        pufferProtocol.registerValidatorKey(data, NO_RESTAKING, numberOfDays, pufETHPermit, vtPermit);

        assertEq(pufferVault.balanceOf(alice), leftOverPufETH, "alice should have some leftover pufETH");
        assertEq(validatorTicket.balanceOf(alice), 0, "0 vt after for alice");
        assertApproxEqRel(pufferVault.balanceOf(address(pufferProtocol)), bond, 0.002e18, "1 pufETH after");
    }

    // Node operator can deposit both VT and pufETH with .approve
    function test_register_both_approve() external {
        bytes memory pubKey = _getPubKey(bytes32("alice"));
        vm.deal(alice, 10 ether);

        uint256 numberOfDays = 200;
        uint256 amount = pufferOracle.getValidatorTicketPrice() * numberOfDays;

        // Alice mints 2 ETH of pufETH
        vm.startPrank(alice);
        // Alice purchases VT
        validatorTicket.purchaseValidatorTicket{ value: amount }(alice);
        // Purchase pufETH
        pufferVault.depositETH{ value: 1 ether }(alice);

        assertEq(pufferVault.balanceOf(address(pufferProtocol)), 0, "zero pufETH before");
        // 1 wei diff
        assertApproxEqAbs(
            pufferVault.previewRedeem(pufferVault.balanceOf(alice)), 1 ether, 1, "1 pufETH before for alice"
        );
        assertEq(validatorTicket.balanceOf(alice), _upscaleTo18Decimals(numberOfDays), "VT before for alice");

        ValidatorKeyData memory data = _getMockValidatorKeyData(pubKey, NO_RESTAKING);

        uint256 bond = 1 ether;

        pufferVault.approve(address(pufferProtocol), type(uint256).max);
        validatorTicket.approve(address(pufferProtocol), type(uint256).max);

        Permit memory vtPermit = emptyPermit;
        vtPermit.amount = _upscaleTo18Decimals(amount); // upscale to 18 decimals

        Permit memory pufETHPermit = emptyPermit;
        pufETHPermit.amount = pufferVault.convertToShares(bond);

        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, 0, NO_RESTAKING, true);
        pufferProtocol.registerValidatorKey(data, NO_RESTAKING, numberOfDays, pufETHPermit, vtPermit);

        assertEq(pufferVault.balanceOf(alice), 0, "0 pufETH after for alice");
        assertEq(validatorTicket.balanceOf(alice), 0, "0 vt after for alice");
        // 1 wei diff
        assertApproxEqAbs(
            pufferVault.previewRedeem(pufferVault.balanceOf(address(pufferProtocol))), bond, 1, "1 pufETH after"
        );
    }

    // Node operator can pay for pufETH with ETH and use Permit for VT
    function test_register_pufETH_pay_vt_approve() external {
        bytes memory pubKey = _getPubKey(bytes32("alice"));
        vm.deal(alice, 10 ether);

        uint256 numberOfDays = 30;
        uint256 amount = pufferOracle.getValidatorTicketPrice() * numberOfDays;

        // Alice mints 2 ETH of pufETH
        vm.startPrank(alice);
        // Alice purchases VT
        validatorTicket.purchaseValidatorTicket{ value: amount }(alice);

        assertEq(pufferVault.balanceOf(address(pufferProtocol)), 0, "zero pufETH before");
        assertEq(pufferVault.balanceOf(alice), 0, "0 pufETH before for alice");
        assertEq(validatorTicket.balanceOf(alice), _upscaleTo18Decimals(numberOfDays), "VT before for alice");

        ValidatorKeyData memory data = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        // Generate Permit data for 2 pufETH to the protocol
        Permit memory permit = _signPermit(
            _testTemps("alice", address(pufferProtocol), _upscaleTo18Decimals(amount), block.timestamp),
            validatorTicket.DOMAIN_SEPARATOR()
        );

        // Alice is using SGX
        uint256 bond = 1 ether;

        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, 0, NO_RESTAKING, true);
        pufferProtocol.registerValidatorKey{ value: bond }(data, NO_RESTAKING, numberOfDays, emptyPermit, permit);

        assertEq(pufferVault.balanceOf(alice), 0, "0 pufETH after for alice");
        assertApproxEqRel(pufferVault.balanceOf(address(pufferProtocol)), 1 ether, pointZeroFive, "~1 pufETH after");
    }

    // Node operator can deposit Bond in pufETH
    function test_register_validator_key_with_permit_reverts_invalid_vt_amount() external {
        bytes memory pubKey = _getPubKey(bytes32("alice"));
        vm.deal(alice, 100 ether);

        // Alice mints 2 ETH of pufETH
        vm.startPrank(alice);
        pufferVault.depositETH{ value: 2 ether }(alice);

        ValidatorKeyData memory data = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        // Generate Permit data for 10 pufETH to the protocol
        Permit memory permit = _signPermit(
            _testTemps("alice", address(pufferProtocol), 0.5 ether, block.timestamp), pufferVault.DOMAIN_SEPARATOR()
        );

        // Underpay VT
        vm.expectRevert();
        pufferProtocol.registerValidatorKey{ value: 0.1 ether }(data, NO_RESTAKING, 60, permit, emptyPermit);

        uint256 vtPrice = pufferOracle.getValidatorTicketPrice();

        // Overpay VT
        vm.expectRevert(IPufferProtocol.InvalidETHAmount.selector);
        pufferProtocol.registerValidatorKey{ value: 5 ether }(data, NO_RESTAKING, 60, permit, emptyPermit);
    }

    function test_validator_griefing_attack() external {
        vm.deal(address(pufferVault), 100 ether);

        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        bytes[] memory guardianSignatures = _getGuardianSignatures(_getPubKey(bytes32("alice")));
        // Register and provision Alice
        // Alice may be an active validator or it can be exited, doesn't matter
        pufferProtocol.provisionNode(guardianSignatures, 0);

        // Register another validator with using the same data
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        // Try to provision it with the original message (replay attack)
        // It should revert
        vm.expectRevert(Unauthorized.selector);
        pufferProtocol.provisionNode(guardianSignatures, 0);
    }

    function test_validator_limit_per_module() external {
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        vm.expectEmit(true, true, true, true);
        emit IPufferProtocol.ValidatorLimitPerModuleChanged(type(uint128).max, 1);
        pufferProtocol.setValidatorLimitPerModule(NO_RESTAKING, 1);

        // Revert if the registration will be over the limit
        uint256 smoothingCommitment = pufferOracle.getValidatorTicketPrice();
        bytes memory pubKey = _getPubKey(bytes32("bob"));
        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, NO_RESTAKING);
        uint256 bond = 1 ether;

        vm.expectRevert(IPufferProtocol.ValidatorLimitForModuleReached.selector);
        pufferProtocol.registerValidatorKey{ value: (smoothingCommitment + bond) }(
            validatorKeyData, NO_RESTAKING, 30, emptyPermit, emptyPermit
        );
    }

    function test_claim_bond_for_single_withdrawal() external {
        _singleWithdrawalMerkleRoot();

        vm.deal(alice, 2 ether);

        vm.startPrank(alice);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        // 1 wei diff
        assertApproxEqAbs(
            pufferVault.previewRedeem(pufferVault.balanceOf(address(pufferProtocol))),
            1 ether,
            1,
            "~1 pufETH in protocol"
        );
        assertApproxEqAbs(
            pufferVault.maxWithdraw(address(pufferProtocol)), 1 ether, 1, "~1 pufETH in protocol maxRedeem"
        );

        Validator memory validator = pufferProtocol.getValidatorInfo(NO_RESTAKING, 0);

        assertEq(validator.bond, pufferVault.balanceOf(address(pufferProtocol)), "alice bond is in the protocol");

        uint256 startTimestamp = 1707411226;

        vm.warp(startTimestamp);

        // Provision validators
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))), 1 ether);

        assertEq(pufferVault.balanceOf(alice), 0, "alice has zero pufETH");

        // 15 days later
        vm.warp(startTimestamp + 16 days);

        // Valid proof
        pufferProtocol.retrieveBond({
            moduleName: NO_RESTAKING,
            validatorIndex: 0,
            blockNumber: 200,
            withdrawalAmount: 32 ether,
            wasSlashed: false,
            validatorStopTimestamp: block.timestamp,
            merkleProof: fullWithdrawalsMerkleProof.getProof(fullWithdrawalMerkleProofData, 0)
        });

        // Alice got the pufETH
        assertGt(pufferVault.balanceOf(alice), 0.9 ether, "alice got the pufETH");
        assertApproxEqAbs(pufferVault.maxWithdraw(alice), 1 ether, 1, "max redeem for alice");
        assertApproxEqAbs(
            pufferVault.previewRedeem(pufferVault.balanceOf(address(alice))), 1 ether, 1, "alice got back ~1 eth"
        );

        bytes32[] memory proof2 = fullWithdrawalsMerkleProof.getProof(fullWithdrawalMerkleProofData, 1);

        // Valid proof for the same validator will revert
        vm.expectRevert();
        pufferProtocol.retrieveBond({
            moduleName: NO_RESTAKING,
            validatorIndex: 0,
            blockNumber: 200,
            withdrawalAmount: 0,
            wasSlashed: false,
            validatorStopTimestamp: block.timestamp,
            merkleProof: proof2
        });

        // Alice doesn't withdraw her VT's right away
        vm.warp(startTimestamp + 50 days);

        // After 50 days she should have 15 VT
        uint256 vtsLeft = pufferProtocol.getValidatorTicketsBalance(alice);
        assertApproxEqRel(vtsLeft, 15 ether, pointZeroZeroOne, "alice has 15 VTs left");
    }

    // Alice deposits VT for herself
    function test_deposit_validator_tickets_approval() public {
        vm.deal(alice, 10 ether);

        uint256 numberOfDays = 200;
        uint256 amount = pufferOracle.getValidatorTicketPrice() * numberOfDays;

        vm.startPrank(alice);
        // Alice purchases VT
        validatorTicket.purchaseValidatorTicket{ value: amount }(alice);

        assertEq(validatorTicket.balanceOf(alice), 200 ether, "alice got 200 VT");
        assertEq(validatorTicket.balanceOf(address(pufferProtocol)), 0, "protocol got 0 VT");

        Permit memory vtPermit = emptyPermit;
        vtPermit.amount = 200 ether;

        // Approve VT
        validatorTicket.approve(address(pufferProtocol), 2000 ether);

        // Deposit for herself
        vm.expectEmit(true, true, true, true);
        emit IPufferProtocol.ValidatorTicketsDeposited(alice, alice, 200 ether);
        pufferProtocol.depositValidatorTickets(vtPermit, alice);

        assertEq(validatorTicket.balanceOf(address(pufferProtocol)), 200 ether, "protocol got 200 VT");
        assertEq(validatorTicket.balanceOf(address(alice)), 0, "alice got 0");
    }

    // Alice deposits VT for bob
    function test_deposit_validator_tickets_permit_for_bob() public {
        vm.deal(alice, 10 ether);

        uint256 numberOfDays = 200;
        uint256 amount = pufferOracle.getValidatorTicketPrice() * numberOfDays;

        vm.startPrank(alice);
        // Alice purchases VT
        validatorTicket.purchaseValidatorTicket{ value: amount }(alice);

        assertEq(validatorTicket.balanceOf(alice), 200 ether, "alice got 200 VT");
        assertEq(validatorTicket.balanceOf(address(pufferProtocol)), 0, "protocol got 0 VT");

        // Sign the permit
        Permit memory vtPermit = _signPermit(
            _testTemps("alice", address(pufferProtocol), _upscaleTo18Decimals(numberOfDays), block.timestamp),
            validatorTicket.DOMAIN_SEPARATOR()
        );

        address bob = makeAddr("bob");

        // Deposit for Bob
        vm.expectEmit(true, true, true, true);
        emit IPufferProtocol.ValidatorTicketsDeposited(bob, alice, 200 ether);
        pufferProtocol.depositValidatorTickets(vtPermit, bob);

        assertEq(pufferProtocol.getValidatorTicketsBalance(bob), 200 ether, "bob got the VTS in the protocol");
        assertEq(pufferProtocol.getValidatorTicketsBalance(alice), 0, "alice got no VTS in the protocol");
    }

    function test_changeMinimumVTAmount() public {
        assertEq(pufferProtocol.getMinimumVtAmount(), 28 ether, "initial value");

        vm.startPrank(DAO);
        pufferProtocol.changeMinimumVTAmount(50 ether);

        assertEq(pufferProtocol.getMinimumVtAmount(), 50 ether, "value after change");
    }

    function test_vt_balance_single_validator() public {
        vm.deal(alice, 10 ether);

        vm.startPrank(alice);
        // Register Validator key registers validator with 30 VTs
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        // Alice registered validator on block.timestamp = 1
        uint256 balance = pufferProtocol.getValidatorTicketsBalance(alice);

        uint256 startTimestamp = 1707411226;

        // advance block timestamp
        vm.warp(startTimestamp);

        // Alice has 30 VTs because her validator is not yet provisioned
        assertEq(balance, 30 ether, "alice should have 30 VTs locked in the protocol");

        // The wait queue is 1 days, the guardians provision the validator with 1 day offset
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))), 1 ether);

        // We offset the timestamp to + 1 days, Alice should still have 30 VT (because the validating is not live yet)
        vm.warp(startTimestamp + 1 days);

        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice),
            30 ether,
            pointZeroZeroOne,
            "alice should still have ~ 30 because VTS"
        );

        // + 1 day offset + 1 day validating
        vm.warp(startTimestamp + 2 days);

        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice), 29 ether, pointZeroZeroOne, "alice should have ~29 VTS"
        );

        // 1 days for the validator start + 20 days
        vm.warp(startTimestamp + 21 days); // 20 days in seconds

        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice), 10 ether, pointZeroZeroOne, "alice should have ~10 VTS"
        );
    }

    function test_vt_balance_different_provision_time() public {
        vm.deal(alice, 10 ether);

        vm.startPrank(alice);
        // Register Validator key registers validator with 30 VTs
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        // Alice registered validator on block.timestamp = 1
        uint256 balance = pufferProtocol.getValidatorTicketsBalance(alice);

        uint256 startTimestamp = 1707411226;

        // advance block timestamp
        vm.warp(startTimestamp);

        // Alice has 90 VTs because her validator is not yet provisioned
        assertEq(balance, 90 ether, "alice should have 90 VTs locked in the protocol");

        // The wait queue is 3 days, the guardians provision the validator with 3 days offset, we credit alice 3 virtual VT's
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))), 3 ether);

        // We offset the timestamp to + 2 days, Alice should still have 90 VT (because the validating is not live yet)
        vm.warp(startTimestamp + 2 days);

        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice),
            91 ether,
            pointZeroZeroOne,
            "alice should still have ~ 91 VTS (+1 for offset)"
        );

        // At t + 2 days the new validator gets provisioned with 2 days queue
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))), 2 ether);

        // 90 is the original deposit, +3 virtual for the first validator, but this is t+2 days, so it is +1, and +2 for this valdiator
        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice),
            93 ether,
            pointZeroZeroOne,
            "alice should still have ~ 93 VTS"
        );

        // + 3 day offset + 1 day validating
        vm.warp(startTimestamp + 4 days);

        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice), 89 ether, pointZeroZeroOne, "alice should have ~89 VTS"
        );

        // Validator 1 - 11 days of validating
        // Validator 2 - 10 days of validating (provisioning happened T+2 with 2 days offset)
        vm.warp(startTimestamp + 14 days); // 20 days in seconds

        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice), 69 ether, pointZeroZeroOne, "alice should have ~69 VTS"
        );
    }

    // Alice tries to withdraw all VT before provisioning
    function test_withdraw_vt_before_provisioning() public {
        vm.deal(alice, 10 ether);

        vm.startPrank(alice);

        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        // Revert saying that at least 28 VT must be left in the protocol
        vm.expectRevert(
            abi.encodeWithSelector(IPufferProtocol.InvalidValidatorTicketAmount.selector, 30 ether, 28 ether)
        );
        pufferProtocol.withdrawValidatorTickets(30 ether, alice);

        address bob = makeAddr("bob");

        assertEq(validatorTicket.balanceOf(bob), 0, "bob 0 VT");

        // Alice can withdraw 2 VT to bob
        pufferProtocol.withdrawValidatorTickets(2 ether, bob);

        assertEq(validatorTicket.balanceOf(bob), 2 ether, "bob got 2 VT");
        assertEq(validatorTicket.balanceOf(alice), 0, "alice 0 VT");
    }

    function test_register_skip_provision_withdraw_vt() public {
        vm.deal(alice, 10 ether);

        vm.startPrank(alice);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice), 30 ether, pointZeroZeroOne, "alice should have ~30 VTS"
        );

        pufferProtocol.skipProvisioning(NO_RESTAKING, _getGuardianSignaturesForSkipping());

        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice),
            20 ether,
            pointZeroZeroOne,
            "alice should have ~20 VTS -10 penalty"
        );

        pufferProtocol.withdrawValidatorTickets(uint96(20 ether), alice);

        assertEq(validatorTicket.balanceOf(alice), 20 ether, "alice got her VT");
    }

    // Alice has two validators, stops one, registers and provisions another one, and after some time claims the bond for the stopped
    function test_stop_validator_provision_another_claim_bond_for_the_first() public {
        _setupMerkleRoot();

        vm.deal(alice, 10 ether);

        vm.startPrank(alice);
        // Register 2 Validators, 2x30 VT
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        uint256 startFirstValidatorTimestamp = 1707411226;

        vm.warp(startFirstValidatorTimestamp);

        // Provision 2 validators in the same timestamp
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))), 1 ether);
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))), 1 ether);

        vm.warp(startFirstValidatorTimestamp + 5 days);

        // 2 Validators are consuming 2x4 VT's
        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice), 82 ether, pointZeroZeroOne, "alice should have ~ 82 VTS"
        );

        bytes32[] memory aliceProof = fullWithdrawalsMerkleProof.getProof(fullWithdrawalMerkleProofData, 0);

        vm.warp(startFirstValidatorTimestamp + 11 days);

        // 2 Validators are consuming 2x10 VT's
        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice), 70 ether, pointZeroZeroOne, "alice should have ~ 70 VTS"
        );

        // This will think that the validator that exited is still active
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))), 1 ether);

        // 2 Validators are consuming 2x10 VT's + 1 virtual
        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice), 71 ether, pointZeroZeroOne, "alice should have ~ 71 VTS"
        );

        // Valid proof
        pufferProtocol.retrieveBond({
            moduleName: NO_RESTAKING,
            validatorIndex: 0,
            blockNumber: 100,
            withdrawalAmount: 32 ether,
            wasSlashed: false,
            validatorStopTimestamp: block.timestamp - 5 days, // 5 days ago
            merkleProof: aliceProof
        });

        assertApproxEqRel(
            validatorTicket.balanceOf(address(pufferProtocol)), 71 ether, pointZeroZeroOne, "real vt balance"
        );

        // Alice should have + 5 VT's because of the validator stop timestamp
        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice), 76 ether, pointZeroZeroOne, "alice should have ~ 76 VTS"
        );
    }

    function test_vt_balance_multiple_validators() public {
        vm.deal(alice, 10 ether);

        vm.startPrank(alice);
        // Register 3 Validators, 3x30 VT
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);
        _registerValidatorKey(bytes32("alice"), NO_RESTAKING);

        // Alice registered validator on block.timestamp = 1
        uint256 balance = pufferProtocol.getValidatorTicketsBalance(alice);

        uint256 startFirstValidatorTimestamp = 1707411226;

        // advance block timestamp
        vm.warp(startFirstValidatorTimestamp);

        // Alice has 90 VTs because no validators are provisioned
        assertEq(balance, 90 ether, "alice should have 30 VTs locked in the protocol");

        // The wait queue is 1 days, the guardians provision the validator with 1 day offset
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))), 1 ether);

        // We offset the timestamp to + 1 days, Alice should still have 30 VT (because the validating is not live yet)
        vm.warp(startFirstValidatorTimestamp + 1 days);

        // At this point the Validator 1 is live
        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice),
            90 ether,
            pointZeroZeroOne,
            "alice should still have ~ 90 because VTS"
        );

        // Validator 1
        // + 1 day offset + 10 day validating
        uint256 newTime = startFirstValidatorTimestamp + 11 days;
        vm.warp(newTime);

        // Validator 1 has been active for 10 days
        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice), 80 ether, pointZeroZeroOne, "alice should have ~80 VTS"
        );

        // Now we provision another Validator with 1 days offset
        pufferProtocol.provisionNode(_getGuardianSignatures(_getPubKey(bytes32("alice"))), 1 ether);

        // VT balance should be 80, but because one validator just got provisioned
        // +1 is because of the offset, a validator just got provisioned with a wait time of 1 day
        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice), 81 ether, pointZeroZeroOne, "alice should have ~81 VTS"
        );

        // Advance the time to start + 6 days
        vm.warp(newTime + 6 days);

        // That means that the Validator 2 is active for 5 days
        // Validator 1 active for 16 days
        assertApproxEqRel(
            pufferProtocol.getValidatorTicketsBalance(alice), 69 ether, pointZeroZeroOne, "alice should have ~69 VTS"
        );
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
            pendingIdx,
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

    function _getPubKey(bytes32 pubKeyPart) internal pure returns (bytes memory) {
        return bytes.concat(abi.encodePacked(pubKeyPart), bytes16(""));
    }

    function _singleWithdrawalMerkleRoot() public {
        address NoRestakingModule = pufferProtocol.getModuleAddress(NO_RESTAKING);

        // We are simulating 1 full withdrawals
        address[] memory modules = new address[](1);
        modules[0] = NoRestakingModule;

        // Give funds to modules
        vm.deal(modules[0], 200 ether);

        // Amounts of full withdrawals that we want to move from modules to pools
        uint256[] memory amounts = new uint256[](1);
        // For no restaking module
        // Assume that the first withdrawal is over 32 ETH, but the guardians will we cap it to 32 ETH, the rest stays in module for rewards withdrawal
        amounts[0] = 32 ether;

        MerkleProofData[] memory validatorExits = new MerkleProofData[](2);
        // Generate a normal proof
        validatorExits[0] = MerkleProofData({ moduleName: NO_RESTAKING, index: 0, amount: 32 ether, wasSlashed: 0 });
        // Generate a zero proof for the same validator index
        validatorExits[1] = MerkleProofData({ moduleName: NO_RESTAKING, index: 0, amount: 32 ether, wasSlashed: 0 });
        bytes32 merkleRoot = _buildMerkleProof(validatorExits);

        // Assert starting state of the pools
        assertEq(address(pufferVault).balance, 1000 ether, "starting pool balance");

        bytes[] memory signatures = _getGuardianEOASignatures(
            LibGuardianMessages._getPostFullWithdrawalsRootMessage(merkleRoot, 200, modules, amounts)
        );

        // Submit a valid proof
        pufferProtocol.postFullWithdrawalsRoot({
            root: merkleRoot,
            blockNumber: 200,
            modules: modules,
            amounts: amounts,
            guardianSignatures: signatures
        });

        assertEq(address(pufferVault).balance, 1032 ether, "ending pool balance");
    }

    // Sets the merkle root and makes sure that the funds get split between WithdrawalPool and PufferPool ASAP
    function _setupMerkleRoot() public {
        // Create EIGEN_DA module
        pufferProtocol.createPufferModule(EIGEN_DA, "", address(0));
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
        // The second withdrawal is 3.16 (inactivity leak)
        amounts[0] = 32 ether + 31.6 ether;
        amounts[1] = 31 ether; // got slashed

        MerkleProofData[] memory validatorExits = new MerkleProofData[](3);
        validatorExits[0] = MerkleProofData({ moduleName: NO_RESTAKING, index: 0, amount: 32 ether, wasSlashed: 0 });
        validatorExits[1] = MerkleProofData({ moduleName: EIGEN_DA, index: 0, amount: 31 ether, wasSlashed: 1 });
        validatorExits[2] = MerkleProofData({ moduleName: NO_RESTAKING, index: 1, amount: 31.6 ether, wasSlashed: 0 });
        bytes32 merkleRoot = _buildMerkleProof(validatorExits);

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

        // Total withdrawal eth is 32 + 31 + 31.6 = 94.6 and the vault has starting balance of 1000 ETH
        assertEq(address(pufferVault).balance, 1094.6 ether, "ending pool balance");
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

    /**
     * @dev Registers validator key and pays for everything in ETH
     */
    function _registerValidatorKey(bytes32 pubKeyPart, bytes32 moduleName) internal {
        uint256 numberOfDays = 30;
        uint256 vtPrice = pufferOracle.getValidatorTicketPrice() * numberOfDays;

        bytes memory pubKey = _getPubKey(pubKeyPart);

        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, moduleName);

        uint256 idx = pufferProtocol.getPendingValidatorIndex(moduleName);

        uint256 bond = 1 ether;

        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, idx, moduleName, true);
        pufferProtocol.registerValidatorKey{ value: (vtPrice + bond) }(
            validatorKeyData, moduleName, 30, emptyPermit, emptyPermit
        );
    }

    function _upscaleTo18Decimals(uint256 amount) internal pure returns (uint256) {
        return amount * 1 ether;
    }
}

struct MerkleProofData {
    bytes32 moduleName;
    uint256 index;
    uint256 amount;
    uint8 wasSlashed;
}
