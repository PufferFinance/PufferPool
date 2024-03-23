// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { TestHelper } from "../helpers/TestHelper.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { IPufferModuleManager } from "puffer/interface/IPufferModuleManager.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { LibGuardianMessages } from "puffer/LibGuardianMessages.sol";
import { BeaconChainProofs } from "eigenlayer/libraries/BeaconChainProofs.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { Initializable } from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";
import { Merkle } from "murky/Merkle.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";
import { Unauthorized } from "puffer/Errors.sol";
import { ROLE_ID_OPERATIONS_PAYMASTER } from "pufETHScript/Roles.sol";
import { IERC20 } from "openzeppelin/token/ERC20/IERC20.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IRestakingOperator } from "puffer/interface/IRestakingOperator.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract PufferModuleUpgrade {
    function getMagicValue() external pure returns (uint256) {
        return 1337;
    }
}

contract PufferModuleManagerTest is TestHelper {
    Merkle rewardsMerkleProof;
    bytes32[] rewardsMerkleProofData;

    bytes32 CRAZY_GAINS = bytes32("CRAZY_GAINS");

    function setUp() public override {
        super.setUp();

        vm.deal(address(this), 1000 ether);

        vm.startPrank(timelock);
        accessManager.grantRole(ROLE_ID_OPERATIONS_PAYMASTER, address(this), 0);
        vm.stopPrank();

        _skipDefaultFuzzAddresses();
    }

    function test_beaconUpgrade() public {
        address moduleBeacon = pufferModuleManager.PUFFER_MODULE_BEACON();

        vm.startPrank(DAO);
        pufferProtocol.createPufferModule(bytes32("DEGEN"));
        vm.stopPrank();

        // No restaking is a custom default module (non beacon upgradeable)
        (bool success,) = pufferProtocol.getModuleAddress(bytes32("DEGEN")).call(
            abi.encodeCall(PufferModuleUpgrade.getMagicValue, ())
        );

        assertTrue(!success, "should not succeed");

        PufferModuleUpgrade upgrade = new PufferModuleUpgrade();

        vm.startPrank(DAO);
        accessManager.execute(moduleBeacon, abi.encodeCall(UpgradeableBeacon.upgradeTo, address(upgrade)));
        vm.stopPrank();

        (bool s, bytes memory data) = pufferProtocol.getModuleAddress(bytes32("DEGEN")).call(
            abi.encodeCall(PufferModuleUpgrade.getMagicValue, ())
        );
        assertTrue(s, "should succeed");
        assertEq(abi.decode(data, (uint256)), 1337, "got the number");
    }

    function test_createPufferModule(bytes32 moduleName) public {
        address module = _createPufferModule(moduleName);
        assertEq(PufferModule(payable(module)).NAME(), moduleName, "bad name");
    }

    // Reverts for everybody else
    function tes_postRewardsRootReverts(bytes32 moduleName, address sender, bytes32 merkleRoot, uint256 blockNumber)
        public
    {
        address module = _createPufferModule(moduleName);

        vm.assume(sender != address(pufferProtocol.GUARDIAN_MODULE()));

        vm.expectRevert();
        PufferModule(payable(module)).postRewardsRoot(merkleRoot, blockNumber, new bytes[](3));
    }

    function test_donation(bytes32 moduleName) public {
        address module = _createPufferModule(moduleName);
        (bool s,) = address(module).call{ value: 5 ether }("");
        assertTrue(s);
    }

    function test_postRewardsRoot(bytes32 merkleRoot, uint256 blockNumber) public {
        address module = _createPufferModule(CRAZY_GAINS);

        vm.assume(PufferModule(payable(module)).getLastProofOfRewardsBlock() < blockNumber);

        bytes32 signedMessageHash =
            LibGuardianMessages._getModuleRewardsRootMessage(CRAZY_GAINS, merkleRoot, blockNumber);

        bytes[] memory signatures = _getGuardianEOASignatures(signedMessageHash);

        PufferModule(payable(module)).postRewardsRoot(merkleRoot, blockNumber, signatures);
    }

    // Collecting the rewards as a node operator
    function test_collect_rewards(bytes32 moduleName) public {
        vm.assume(pufferProtocol.getModuleAddress(moduleName) == address(0));
        address module = _createPufferModule(moduleName);

        // 3 validators got the rewards
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");
        address charlie = makeAddr("charlie");

        // Build a merkle proof for that
        MerkleProofData[] memory validatorRewards = new MerkleProofData[](3);
        validatorRewards[0] = MerkleProofData({ node: alice, amount: 0.01308 ether });
        validatorRewards[1] = MerkleProofData({ node: bob, amount: 0.013 ether });
        validatorRewards[2] = MerkleProofData({ node: charlie, amount: 1 });

        vm.deal(module, 0.01308 ether + 0.013 ether + 1);
        bytes32 merkleRoot = _buildMerkleProof(validatorRewards);

        bytes32 signedMessageHash = LibGuardianMessages._getModuleRewardsRootMessage(moduleName, merkleRoot, 50);
        bytes[] memory signatures = _getGuardianEOASignatures(signedMessageHash);

        // Post merkle proof with valid guardian signatures
        PufferModule(payable(module)).postRewardsRoot(merkleRoot, 50, signatures);

        // Try posting for block number lower than 50
        vm.expectRevert(abi.encodeWithSelector(IPufferModule.InvalidBlockNumber.selector, 49));
        PufferModule(payable(module)).postRewardsRoot(merkleRoot, 49, signatures);

        // Claim the rewards

        uint256[] memory blockNumbers = new uint256[](1);
        blockNumbers[0] = 50;

        // Alice amount
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 0.01308 ether;

        bytes32[][] memory aliceProofs = new bytes32[][](1);
        aliceProofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 0);

        assertEq(alice.balance, 0, "alice should start with zero balance");

        vm.startPrank(alice);
        PufferModule(payable(module)).collectRewards({
            node: alice,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: aliceProofs
        });
        assertEq(alice.balance, 0.01308 ether, "alice should end with 0.01308 ether");

        // Double claim in different transactions should revert
        vm.expectRevert(abi.encodeWithSelector(IPufferModule.AlreadyClaimed.selector, blockNumbers[0], alice));
        PufferModule(payable(module)).collectRewards({
            node: alice,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: aliceProofs
        });

        // Bob claiming with Alice's proof (alice already claimed)
        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSelector(IPufferModule.AlreadyClaimed.selector, blockNumbers[0], alice));
        PufferModule(payable(module)).collectRewards({
            node: alice,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: aliceProofs
        });

        bytes32[][] memory bobProofs = new bytes32[][](1);
        bobProofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 1);
        bytes32[][] memory charlieProofs = new bytes32[][](1);
        charlieProofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 2);

        // Mutate amounts, set Charlie's amount
        amounts[0] = 1;

        // Bob claiming with Charlie's prof (charlie did not claim yet)
        // It will revert with nothing to claim because the proof is not valid for bob
        vm.expectRevert(abi.encodeWithSelector(IPufferModule.NothingToClaim.selector, bob));
        PufferModule(payable(module)).collectRewards({
            node: bob,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: charlieProofs
        });

        // Bob claiming for charlie (bob is msg.sender)
        PufferModule(payable(module)).collectRewards({
            node: charlie,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: charlieProofs
        });

        assertEq(charlie.balance, 1, "1 wei for charlie");

        // Mutate amounts, set Charlie's amount
        amounts[0] = 0.013 ether;

        PufferModule(payable(module)).collectRewards({
            node: bob,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: bobProofs
        });

        assertEq(bob.balance, 0.013 ether, "bob rewards");
    }

    function test_callDelegateTo(
        bytes32 moduleName,
        address operator,
        ISignatureUtils.SignatureWithExpiry memory signatureWithExpiry,
        bytes32 approverSalt
    ) public {
        vm.assume(pufferProtocol.getModuleAddress(moduleName) == address(0));

        address module = _createPufferModule(moduleName);
        vm.startPrank(DAO);

        vm.expectRevert(Unauthorized.selector);
        PufferModule(payable(module)).callDelegateTo(operator, signatureWithExpiry, approverSalt);

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.PufferModuleDelegated(moduleName, operator);

        pufferModuleManager.callDelegateTo(moduleName, operator, signatureWithExpiry, approverSalt);

        vm.stopPrank();
    }

    function test_callUndelegate(bytes32 moduleName) public {
        vm.assume(pufferProtocol.getModuleAddress(moduleName) == address(0));

        address module = _createPufferModule(moduleName);
        vm.startPrank(DAO);

        vm.expectRevert(Unauthorized.selector);
        PufferModule(payable(module)).callUndelegate();

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.PufferModuleUndelegated(moduleName);

        pufferModuleManager.callUndelegate(moduleName);

        vm.stopPrank();
    }

    function test_module_has_eigenPod(bytes32 moduleName) public {
        vm.assume(pufferProtocol.getModuleAddress(moduleName) == address(0));
        address module = _createPufferModule(moduleName);

        assertTrue(PufferModule(payable(module)).getEigenPod() != address(0), "should have EigenPod");
    }

    function test_rewards_claiming_from_eigenlayer(bytes32 moduleName) public {
        vm.assume(pufferProtocol.getModuleAddress(moduleName) == address(0));
        _createPufferModule(moduleName);

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.WithdrawalsQueued(moduleName, 1 ether, bytes32("123"));
        pufferModuleManager.callQueueWithdrawals(moduleName, 1 ether);
    }

    function test_callWithdrawNonBeaconChainETHBalanceWei(bytes32 moduleName) public {
        vm.assume(pufferProtocol.getModuleAddress(moduleName) == address(0));
        _createPufferModule(moduleName);

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.NonBeaconChainETHBalanceWithdrawn(moduleName, 1 ether);
        pufferModuleManager.callWithdrawNonBeaconChainETHBalanceWei(moduleName, 1 ether);
    }

    function test_callVerifyWithdrawalCredentials(bytes32 moduleName) public {
        vm.assume(pufferProtocol.getModuleAddress(moduleName) == address(0));
        _createPufferModule(moduleName);

        uint64 oracleTimestamp;
        BeaconChainProofs.StateRootProof memory stateRootProof;
        uint40[] memory validatorIndices;
        bytes[] memory validatorFieldsProofs;
        bytes32[][] memory validatorFields;

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.ValidatorCredentialsVerified(moduleName, validatorIndices);
        pufferModuleManager.callVerifyWithdrawalCredentials(
            moduleName, oracleTimestamp, stateRootProof, validatorIndices, validatorFieldsProofs, validatorFields
        );
    }

    function test_completeQueuedWithdrawals(bytes32 moduleName) public {
        vm.assume(pufferProtocol.getModuleAddress(moduleName) == address(0));
        address module = _createPufferModule(moduleName);

        IDelegationManager.Withdrawal[] memory withdrawals;
        IERC20[][] memory tokens;
        uint256[] memory middlewareTimesIndexes;

        emit IPufferModuleManager.CompletedQueuedWithdrawals(moduleName, 0);
        pufferModuleManager.callCompleteQueuedWithdrawals(moduleName, withdrawals, tokens, middlewareTimesIndexes);
    }

    function test_verifyAndProcessWithdrawals(bytes32 moduleName) public {
        vm.assume(pufferProtocol.getModuleAddress(moduleName) == address(0));
        _createPufferModule(moduleName);

        uint64 oracleTimestamp;
        BeaconChainProofs.StateRootProof memory stateRootProof;
        BeaconChainProofs.WithdrawalProof[] memory withdrawalProofs;
        bytes[] memory validatorFieldsProofs;
        bytes32[][] memory validatorFields;
        bytes32[][] memory withdrawalFields;

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.VerifiedAndProcessedWithdrawals(moduleName, validatorFields, withdrawalFields);
        pufferModuleManager.callVerifyAndProcessWithdrawals(
            moduleName,
            oracleTimestamp,
            stateRootProof,
            withdrawalProofs,
            validatorFieldsProofs,
            validatorFields,
            withdrawalFields
        );
    }

    function test_updateAVSRegistrationSignatureProof() public {
        (address signer, uint256 pk) = makeAddrAndKey("signer");

        vm.startPrank(DAO);

        IRestakingOperator operator = _createRestakingOperator();

        bytes32 salt = 0xdebc2c61283b511dc62175c508bc9c6ad8ca754ba918164e6a9b19765c98006d;
        bytes32 digestHash = keccak256(
            abi.encode("OPERATOR_AVS_REGISTRATION_TYPEHASH", address(operator), address(1234), salt, block.timestamp)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digestHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(Unauthorized.selector);
        operator.updateSignatureProof(digestHash, signer);

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.AVSRegistrationSignatureProofUpdated(address(operator), digestHash, signer);
        pufferModuleManager.updateAVSRegistrationSignatureProof(operator, digestHash, signer);

        assertTrue(
            SignatureChecker.isValidERC1271SignatureNow(address(operator), digestHash, signature), "signer proof"
        );

        bytes32 fakeDigestHash = keccak256(abi.encode(digestHash));

        assertFalse(
            SignatureChecker.isValidERC1271SignatureNow(address(operator), fakeDigestHash, signature), "signer proof"
        );

        vm.stopPrank();
    }

    function _createPufferModule(bytes32 moduleName) internal returns (address module) {
        vm.assume(pufferProtocol.getModuleAddress(moduleName) == address(0));
        vm.startPrank(DAO);
        vm.expectEmit(true, true, true, true);
        emit Initializable.Initialized(1);
        module = pufferProtocol.createPufferModule(moduleName);

        vm.stopPrank();
    }

    function _buildMerkleProof(MerkleProofData[] memory validatorRewards) internal returns (bytes32 root) {
        rewardsMerkleProof = new Merkle();

        rewardsMerkleProofData = new bytes32[](validatorRewards.length);

        for (uint256 i = 0; i < validatorRewards.length; ++i) {
            MerkleProofData memory validatorData = validatorRewards[i];
            rewardsMerkleProofData[i] =
                keccak256(bytes.concat(keccak256(abi.encode(validatorData.node, validatorData.amount))));
        }

        root = rewardsMerkleProof.getRoot(rewardsMerkleProofData);
    }

    function _createRestakingOperator() internal returns (IRestakingOperator) {
        IRestakingOperator operator = pufferModuleManager.createNewRestakingOperator({
            metadataURI: "https://puffer.fi/metadata.json",
            delegationApprover: address(0),
            stakerOptOutWindowBlocks: 0
        });

        IDelegationManager.OperatorDetails memory details =
            operator.EIGEN_DELEGATION_MANAGER().operatorDetails(address(operator));
        assertEq(details.delegationApprover, address(0), "delegation approver");
        assertEq(details.stakerOptOutWindowBlocks, 0, "blocks");
        return operator;
    }
}

struct MerkleProofData {
    address node;
    uint256 amount;
}
