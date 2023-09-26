// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title IPufferOwner
 * @author Puffer Finance
 * @notice Interface for the contract owner
 */
interface IPufferOwner {
    /**
     * TODO:
     */
    function setGuardianEnclaveMeasurements(bytes32 mrenclave, bytes32 mrsigner) external;

    /**
     * @notice Pauses the smart contract
     */
    function pause() external;

    /**
     * @notice Unpauses the smart contract
     */
    function resume() external;

    /**
     * @notice Changes the protocol fee rate to `protocolFeeRate`
     *         Protocol fee is a percentage of funds going to the Puffer treasury and it is being taken only from the rewards
     */
    function setProtocolFeeRate(uint256 protocolFeeRate) external;
}
