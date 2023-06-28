// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

interface RewardSplitterInterface {
    function canSkim() external view returns (bool);

    function withdraw(address payable _to) external returns (uint256);

    function skim(address payable _to) external returns (uint256);
}
