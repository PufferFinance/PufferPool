// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";
import { NoRestakingStrategy } from "puffer/NoRestakingStrategy.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";

contract PufferPoolTest is TestHelper {
    using ECDSA for bytes32;

    NoRestakingStrategy strategy;

    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();
        _skipDefaultFuzzAddresses();

        strategy = NoRestakingStrategy(payable(pufferProtocol.getStrategyAddress(NO_RESTAKING)));
    }

    // Test setup
    function testSetup() public {
        address noRestakingStrategy = pufferProtocol.getStrategyAddress(NO_RESTAKING);
        assertEq(IPufferStrategy(noRestakingStrategy).NAME(), NO_RESTAKING, "bad name");
    }

    // Reverts for everybody else
    function testPostRewardsRootReverts(address sender, bytes32 merkleRoot, uint256 blockNumber) public {
        vm.assume(sender != address(guardiansSafe));

        vm.expectRevert();
        strategy.postRewardsRoot(merkleRoot, blockNumber);
    }

    // Works for guardians
    function testPostRewardsRoot(bytes32 merkleRoot, uint256 blockNumber) public {
        vm.assume(strategy.getLastProofOfRewardsBlock() < blockNumber);
        vm.startPrank(address(guardiansSafe));
        strategy.postRewardsRoot(merkleRoot, blockNumber);
    }

    // Donation should work
    function testDonation() public {
        (bool s,) = address(strategy).call{ value: 5 ether }("");
        assertTrue(s);
    }

    function testCollectRewards() public {
        // Give eth to strategy
        vm.deal(address(strategy), 1000 ether);

        // Read data

        vm.startPrank(address(guardiansSafe));
        // strategy.postRewardsRoot(merkleRoot, blockNumber);

        // Collect rewards
    }
}
