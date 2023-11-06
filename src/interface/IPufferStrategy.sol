// SPDX-License-Identifier: GPL-3.0
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

    /**
     * @notice Function callable only by PufferProtocol
     * @param to is the destination address
     * @param amount is the ETH amount in wei
     * @param data is the calldata
     */
    function call(address to, uint256 amount, bytes calldata data)
        external
        returns (bool success, bytes memory response);
}
