// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title IETHDepositor interface
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 * @notice Interface for interacting with ETHDepositor smart contract
 */
interface IETHDepositor {
    /**
     * @notice Deposits ETH to PufferPool
     * @param recipientAddress is the address of the pufETH recipient
     * @return shares is the `pufETH` amount minted to `recipientAddress`
     */
    function deposit(address recipientAddress) external payable returns (uint256 shares);
}
