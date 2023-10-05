// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";

/**
 * @title IPufferStrategy
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferStrategy {
    /**
     * @notice Returns the address of the owned EigenPod
     */
    function getEigenPod() external view returns (address);

    /**
     * @notice Starts the validator via EigenLayer
     */
    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot) external payable;

    /**
     * @notice Collects the staking rewards only if the validator is not restaking
     */
    function collectRewardsIfNotRestaking() external;

    /**
     * @notice Returns the EigenPodManager
     */
    function EIGEN_POD_MANAGER() external view returns (IEigenPodManager);
}
