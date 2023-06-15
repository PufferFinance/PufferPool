// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

interface RewardSplitterInterface {
    function canSkim() external view;

    function withdraw(
        address balanceReceiver) 
        external;

    function skim(
        address balanceReceiver) 
        external;
}