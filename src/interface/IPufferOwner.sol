// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferPool } from "puffer/interface/IPufferPool.sol";

/**
 * @title IPufferOwner
 * @author Puffer Finance
 * @notice Interface for the contract owner
 */
interface IPufferOwner {
    /**
     * @notice Sets the execution rewards split to `newValue`
     */
    // function setExecutionCommission(uint256 newValue) external;

    /**
     * @notice Sets the consensus rewards split to `newValue`
     */
    // function setConsensusCommission(uint256 newValue) external;

    /**
     * @notice Sets the POD AVS commission to `newValue`
     */
    // function setAvsCommission(uint256 newValue) external;

    /**
     * TODO:
     */
    function setNodeEnclaveMeasurements(bytes32 mrenclave, bytes32 mrsigner) external;

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
     * @notice Changes the `avs` configuration to `configuration`
     */
    function changeAVSConfiguration(address avs, IPufferPool.AVSParams memory configuration) external;

    /**
     * @notice Changes the protocol fee rate to `protocolFeeRate`
     *         Protocol fee is a percentage of funds going to the Puffer treasury and it is being taken only from the rewards
     */
    function setProtocolFeeRate(uint256 protocolFeeRate) external;
}
