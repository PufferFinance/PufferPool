// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { NoRestakingModule } from "puffer/NoRestakingModule.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { LibGuardianMessages } from "puffer/LibGuardianMessages.sol";

contract NoRestakingModuleTest is TestHelper {
    using ECDSA for bytes32;

    NoRestakingModule _noRestakingModule;

    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();
        _skipDefaultFuzzAddresses();

        _noRestakingModule = NoRestakingModule(payable(pufferProtocol.getModuleAddress(NO_RESTAKING)));
    }

    // Test setup
    function testSetup() public {
        address noRestakingModule = pufferProtocol.getModuleAddress(NO_RESTAKING);
        assertEq(IPufferModule(noRestakingModule).NAME(), NO_RESTAKING, "bad name");
    }

    // Reverts for everybody else
    function testPostRewardsRootReverts(address sender, bytes32 merkleRoot, uint256 blockNumber) public {
        vm.assume(sender != address(pufferProtocol.GUARDIAN_MODULE()));

        vm.expectRevert();
        _noRestakingModule.postRewardsRoot(merkleRoot, blockNumber, new bytes[](3));
    }

    // Works for guardians
    function testPostRewardsRoot(bytes32 merkleRoot, uint256 blockNumber) public {
        vm.assume(_noRestakingModule.getLastProofOfRewardsBlock() < blockNumber);

        bytes32 signedMessageHash =
            LibGuardianMessages._getModuleRewardsRootMessage(bytes32("NO_RESTAKING"), merkleRoot, blockNumber);

        bytes[] memory signatures = _getGuardianEOASignatures(signedMessageHash);

        _noRestakingModule.postRewardsRoot(merkleRoot, blockNumber, signatures);
    }

    // Donation should work
    function testDonation() public {
        (bool s,) = address(_noRestakingModule).call{ value: 5 ether }("");
        assertTrue(s);
    }

    // Collecting rewards flow
    function testCollectRewards() public {
        _setupMerkleRoot();

        uint256[] memory blockNumbers = new uint256[](1);
        blockNumbers[0] = 1;

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 16080000000000000;

        bytes32[][] memory merkleProofs = new bytes32[][](1);
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = hex"3c96586c7b865e20062ef47a0faca2d5358ecf9b5ebbef06016a674253b614c7";
        proof[1] = hex"c6f0836b2023b5fd91c6df8de68d3511c0e4e0984cd09df23d26227717a8ccb2";
        merkleProofs[0] = proof;

        assertEq(alice.balance, 0, "alice should start with zero balance");

        vm.startPrank(alice);
        _noRestakingModule.collectRewards({
            node: alice,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: merkleProofs
        });

        // Double claim in different transactions should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                NoRestakingModule.AlreadyClaimed.selector, blockNumbers[0], alice
            )
        );
        _noRestakingModule.collectRewards({
            node: alice,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: merkleProofs
        });
        assertEq(alice.balance, 16080000000000000, "alice should end with 16080000000000000 eth");

        // Bob claiming with Alice's proof
        vm.startPrank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                NoRestakingModule.NothingToClaim.selector, bob
            )
        );
        _noRestakingModule.collectRewards({
            node: bob,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: merkleProofs
        });

        // Bob claiming with a valid proof that is not his
        vm.expectRevert(
            abi.encodeWithSelector(NoRestakingModule.NothingToClaim.selector, bob)
        );
        _noRestakingModule.collectRewards({
            node: bob,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: merkleProofs
        });
    }

    function testDoubleClaimInSameTransaction() public {
        _setupMerkleRoot();

        uint256[] memory blockNumbers = new uint256[](2);
        blockNumbers[0] = 1;
        blockNumbers[1] = 1;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 16080000000000000;
        amounts[1] = 16080000000000000;

        bytes32[][] memory merkleProofs = new bytes32[][](2);
        bytes32[] memory proof = new bytes32[](2);
        bytes32[] memory proof2 = new bytes32[](2);
        proof[0] = hex"3c96586c7b865e20062ef47a0faca2d5358ecf9b5ebbef06016a674253b614c7";
        proof[1] = hex"c6f0836b2023b5fd91c6df8de68d3511c0e4e0984cd09df23d26227717a8ccb2";
        proof2[0] = hex"3c96586c7b865e20062ef47a0faca2d5358ecf9b5ebbef06016a674253b614c7";
        proof2[1] = hex"c6f0836b2023b5fd91c6df8de68d3511c0e4e0984cd09df23d26227717a8ccb2";
        merkleProofs[0] = proof;
        merkleProofs[1] = proof2;

        assertEq(alice.balance, 0, "alice should start with zero balance");

        vm.startPrank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                NoRestakingModule.AlreadyClaimed.selector, blockNumbers[0], alice
            )
        );
        _noRestakingModule.collectRewards({
            node: alice,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: merkleProofs
        });
    }

    // Zero withdrawal reverts
    function testCollectRewardsRevertsForZeroValues() public {
        vm.expectRevert(abi.encodeWithSelector(NoRestakingModule.NothingToClaim.selector, address(0)));
        _noRestakingModule.collectRewards({
            node: address(0),
            blockNumbers: new uint256[](1),
            amounts: new uint256[](1),
            merkleProofs: new bytes32[][](1)
        });
    }

    // Anybody should be able to claim for Charlie, Charlie should get ETH
    function testRewardsClaimingForAnotherUser(address msgSender) public assumeEOA(msgSender) {
        _setupMerkleRoot();

        uint256[] memory blockNumbers = new uint256[](1);
        blockNumbers[0] = 1;

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 16070000000000000;

        bytes32[][] memory merkleProofs = new bytes32[][](1);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = hex"1f10980ebf8a2fa0f1888e174f5487867589d59b15b3845792f5424c7a22e0f0";
        merkleProofs[0] = proof;

        assertEq(charlie.balance, 0, "charlie should start with zero balance");

        // Random msg.sender
        vm.startPrank(msgSender);
        _noRestakingModule.collectRewards({
            node: charlie,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: merkleProofs
        });

        assertEq(charlie.balance, 16070000000000000, "charlie should end with 16070000000000000 balance");
    }

    // Alice Alice claims rewards with 2 proofs
    function testClaimingMultipleProofs() public {
        _setupMerkleRoot();

        uint256[] memory blockNumbers = new uint256[](2);
        blockNumbers[0] = 1;
        blockNumbers[1] = 150;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 16080000000000000;
        amounts[1] = 26080000000000000;

        bytes32[][] memory merkleProofs = new bytes32[][](2);
        bytes32[] memory proof1 = new bytes32[](2);
        // first array of proofs from value 1 (first script)
        proof1[0] = hex"3c96586c7b865e20062ef47a0faca2d5358ecf9b5ebbef06016a674253b614c7";
        proof1[1] = hex"c6f0836b2023b5fd91c6df8de68d3511c0e4e0984cd09df23d26227717a8ccb2";
        bytes32[] memory proof2 = new bytes32[](2);
        // Second array of proofs from value 2 (run script again)
        proof2[0] = hex"7cf8ac19900bd2891ad7ad3bbdef859e7b335aa1fe95774e3ec27eeda71831c8";
        proof2[1] = hex"80d19ea204fac2c5559ba004190fb74186d17b1eb00ddadb5d0c4935e8661a47";
        merkleProofs[0] = proof1;
        merkleProofs[1] = proof2;

        assertEq(alice.balance, 0, "alice should start with zero balance");

        _noRestakingModule.collectRewards({
            node: alice,
            blockNumbers: blockNumbers,
            amounts: amounts,
            merkleProofs: merkleProofs
        });

        assertEq(alice.balance, 42160000000000000, "alice should end non zero balance");
    }

    function testPostingRewardsForSameBlockReverts() public {
        bytes32 merkleRoot1 = hex"415eab63c87f7cb27d1ae7c58d634c68901523ff3773671cbdc09d2b002a80e1";

        bytes32 signedMessageHash =
            LibGuardianMessages._getModuleRewardsRootMessage(bytes32("NO_RESTAKING"), merkleRoot1, 1);

        bytes[] memory signatures = _getGuardianEOASignatures(signedMessageHash);

        // Post two merkle roots
        _noRestakingModule.postRewardsRoot(merkleRoot1, 1, signatures);
        vm.expectRevert(abi.encodeWithSelector(NoRestakingModule.InvalidBlockNumber.selector, 1));
        _noRestakingModule.postRewardsRoot(merkleRoot1, 1, signatures);
    }

    function _setupMerkleRoot() public {
        // Script for generating merkle proofs is in `test/unit/NoRestakingStartegyProofs.js`
        // Merkle roots are hardcoded, we have two of them
        vm.deal(address(_noRestakingModule), 1000 ether);

        bytes32 merkleRoot1 = hex"415eab63c87f7cb27d1ae7c58d634c68901523ff3773671cbdc09d2b002a80e1";
        bytes32 merkleRoot2 = hex"657fabde691fbafeb450b72bf921e575f1f822c2283513b7c67da69e9dac3429";

        bytes32 signedMessageHash1 =
            LibGuardianMessages._getModuleRewardsRootMessage(bytes32("NO_RESTAKING"), merkleRoot1, 1);
        bytes32 signedMessageHash2 =
            LibGuardianMessages._getModuleRewardsRootMessage(bytes32("NO_RESTAKING"), merkleRoot2, 150);

        bytes[] memory signatures1 = _getGuardianEOASignatures(signedMessageHash1);
        bytes[] memory signatures2 = _getGuardianEOASignatures(signedMessageHash2);

        // Post two merkle roots
        _noRestakingModule.postRewardsRoot(merkleRoot1, 1, signatures1);
        _noRestakingModule.postRewardsRoot(merkleRoot2, 150, signatures2);
    }
}
