// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title IPufferOwner
 * @author Puffer Finance
 * @notice Interface for the contract owner
 */
interface IPufferOwner {
    /**
     * @notice Sets the execution rewards split to `newValue`
     */
    function setExecutionRewardsSplit(uint256 newValue) external;

    /**
     * @notice Sets the consensus rewards split to `newValue`
     */
    function setConsensusRewardsSplit(uint256 newValue) external;

    /**
     * @notice Sets the POD AVS comission to `newValue`
     */
    function setPodAVSCommission(uint256 newValue) external;

    /**
     * Changes the {Safe} implementation address to `newSafeImplementation`
     */
    function changeSafeImplementation(address newSafeImplementation) external;

    /**
     * Changes the {Safe} proxy factory address to `newSafeFactory`
     */
    function changeSafeProxyFactory(address newSafeFactory) external;

    /**
     * Pauses the smart contract
     */
    function pause() external;

    /**
     * Unpauses the smart contract
     */
    function resume() external;
}