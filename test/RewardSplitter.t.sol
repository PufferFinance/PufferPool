// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "src/RewardSplitter.sol";

contract TestRewardSplitter is Test {
    address podAddress = address(0);
    address poolAddress = address(1);
    address recipient = address(2);
    uint256 skimThreshold = 2 ether;

    function setUp() public {}

    function newSplitterWithBalance(uint256 balance) public returns (address) {
        // Make sure msg.sender is the pod
        vm.prank(podAddress);
        RewardSplitter s = new RewardSplitter(poolAddress, skimThreshold);
        address splitterAddr = address(s);
        require(s.podAddr() == podAddress, "bad podAddress");
        require(s.poolAddr() == poolAddress, "bad poolAddress");
        vm.stopPrank();

        // Populate contract's balance
        vm.deal(splitterAddr, balance);
        return splitterAddr;
    }

    function testFuzz_newSplitterWithBalance(uint256 balance) public {
        address splitterAddr = newSplitterWithBalance(balance);
        assertEq(balance, splitterAddr.balance);
    }

    function test_skim(uint256 balance) public {
        // uint256 balance = 6 ether;
        address splitterAddr = newSplitterWithBalance(balance);
        RewardSplitter s = RewardSplitter(splitterAddr);

        require(splitterAddr.balance == balance, "splitter initialized incorrectly");
        require(recipient.balance == 0 ether, "recipient initialized incorrectly");

        uint256 skimmed = s.skim(payable(recipient));

        console.log("recipient balance {}", recipient.balance);
        require(recipient.balance + splitterAddr.balance == balance, "eth lost during skim");
        // require(recipient.balance == skimmed, "recipient skimmed wrong amount");
        // require(splitterAddr.balance == balance - skimmed, "splitter contract did not skim eth");

        // Change the caller to a non-owner
        // vm.prank(podAddress);

        // uint256 skimAmount = s.skim();
        // assertEq(s, s)
    }
}
