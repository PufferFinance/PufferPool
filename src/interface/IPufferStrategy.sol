// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title IPufferStrategy
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferStrategy {
    /**
     * @notice Returns the Withdrawal credentials for that strategy
     */
    function getWithdrawalCredentials() external view returns (bytes memory);

    /**
     * @notice Returns the strategy name
     */
    function NAME() external view returns (bytes32);

    /**
     * @notice Starts the validator
     */
    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot) external payable;
}
