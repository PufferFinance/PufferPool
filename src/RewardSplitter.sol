// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { RewardSplitterInterface } from "puffer/interface/RewardSplitterInterface.sol";
import { SignedMath } from "openzeppelin/utils/math/SignedMath.sol";

import { Test } from "forge-std/Test.sol";
import { console } from "forge-std/Test.sol";

contract RewardSplitter is RewardSplitterInterface, Test {
    address public podAddr;
    address public poolAddr;

    // Bypassed by beacon chain
    bool cannotBePaid;

    // T
    int256 MAX_EFFECTIVE_BALANCE = 32;
    uint256 skimThreshold;

    uint256[] scalers;
    uint256[] divisors;

    event SkimmedRewards(uint256 amount);
    event WithdrewRewards(uint256 amount);

    constructor(address _poolAddr, uint256 _skimThreshold) {
        // Expect instantiated from PodAccount
        podAddr = msg.sender;
        poolAddr = _poolAddr;
        skimThreshold = _skimThreshold;
    }

    function canSkim() external view returns (bool) {
        return true;
    }

    function withdraw(address payable _to) external returns (uint256) {
        return 2;
    }

    // return balance if balance < threshold else max(balance - 32, 0)
    function skim(address payable _to) external returns (uint256) {
        uint256 balance = address(this).balance;
        console.log(balance);
        uint256 skimAmount = 0;
        if (balance < skimThreshold) {
            skimAmount = balance;
        } else {
            skimAmount = SignedMath.abs(SignedMath.max(int256(balance) - MAX_EFFECTIVE_BALANCE, 0));
        }

        (bool sent, bytes memory data) = _to.call{ value: skimAmount }("");
        require(sent, "Failed to send Ether");
        return balance;
    }
}
