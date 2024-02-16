// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { TestHelper } from "../helpers/TestHelper.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { LibGuardianMessages } from "puffer/LibGuardianMessages.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { Initializable } from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";
import { Merkle } from "murky/Merkle.sol";

contract PufferModuleUpgrade {
    function getMagicValue() external pure returns (uint256) {
        return 1337;
    }
}

/**
 * @dev A lot of the tests are copied and adapted from NoRestakingModule.t.sol
 */
contract PufferModuleTest is TestHelper {
    Merkle rewardsMerkleProof;
    bytes32[] rewardsMerkleProofData;

    bytes32 CRAZY_GAINS = bytes32("CRAZY_GAINS");

    function setUp() public override {
        super.setUp();

        vm.deal(address(this), 1000 ether);

        _skipDefaultFuzzAddresses();
    }

    function testBeaconUpgrade() public {
        address moduleBeacon = moduleFactory.PUFFER_MODULE_BEACON();

        vm.startPrank(DAO);
        pufferProtocol.createPufferModule(bytes32("DEGEN"), "", address(0));
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

    function testCreatePufferModule(bytes32 moduleName) public {
        address module = _createPufferModule(moduleName);
        assertEq(PufferModule(payable(module)).NAME(), moduleName, "bad name");
    }

    // Reverts for everybody else
    function testPostRewardsRootReverts(bytes32 moduleName, address sender, bytes32 merkleRoot, uint256 blockNumber)
        public
    {
        address module = _createPufferModule(moduleName);

        vm.assume(sender != address(pufferProtocol.GUARDIAN_MODULE()));

        vm.expectRevert();
        PufferModule(payable(module)).postRewardsRoot(merkleRoot, blockNumber, new bytes[](3));
    }

    function testDonation(bytes32 moduleName) public {
        address module = _createPufferModule(moduleName);
        (bool s,) = address(module).call{ value: 5 ether }("");
        assertTrue(s);
    }

    function testPostRewardsRoot(bytes32 merkleRoot, uint256 blockNumber) public {
        address module = _createPufferModule(CRAZY_GAINS);

        vm.assume(PufferModule(payable(module)).getLastProofOfRewardsBlock() < blockNumber);

        bytes32 signedMessageHash =
            LibGuardianMessages._getModuleRewardsRootMessage(CRAZY_GAINS, merkleRoot, blockNumber);

        bytes[] memory signatures = _getGuardianEOASignatures(signedMessageHash);

        PufferModule(payable(module)).postRewardsRoot(merkleRoot, blockNumber, signatures);
    }

    // Collecting non restaking rewards
    function testCollectNoRestakingRewards(bytes32 moduleName) public {
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
        vm.expectRevert(abi.encodeWithSelector(PufferModule.AlreadyClaimed.selector, blockNumbers[0], alice));
        PufferModule(payable(module)).collectRewards({
            node: alice,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: aliceProofs
        });

        // Bob claiming with Alice's proof (alice already claimed)
        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSelector(PufferModule.AlreadyClaimed.selector, blockNumbers[0], alice));
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
        vm.expectRevert(abi.encodeWithSelector(PufferModule.NothingToClaim.selector, bob));
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

    function _createPufferModule(bytes32 moduleName) internal returns (address module) {
        vm.startPrank(DAO);
        vm.expectEmit(true, true, true, true);
        emit Initializable.Initialized(1);
        module = pufferProtocol.createPufferModule(moduleName, "", address(0));
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
}

struct MerkleProofData {
    address node;
    uint256 amount;
}
