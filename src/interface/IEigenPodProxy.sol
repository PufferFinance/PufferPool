// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { BeaconChainProofs } from "eigenlayer/libraries/BeaconChainProofs.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";

/**
 * @title IEigenPodProxy
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 * @notice IEigenPodProxy TODO:
 */
interface IEigenPodProxy {
    /**
     * @dev Thrown if the msg.sender is unauthorized.
     */
    error Unauthorized();

    error ValidatorIsAlreadyStaking();

    /**
     * @dev Thrown if the Eigenlayer AVS is not supported by Puffer Finance
     */
    error AVSNotSupported();

    /**
     * Emitted when the pod rewads recipient is changed from the `oldRecipient` to the `newRecipient`
     */
    event PodRewardsRecipientChanged(address oldRecipient, address newRecipient);

    /**
     * @notice Initializes the proxy contract
     * @param pool is the Manager of Eigen Pod Proxy (PufferPool)
     */
    function initialize(IPufferPool pool) external;

    /**
     * @notice Returns the Eigen pod manager from EigenLayer
     */
    function getEigenPodManager() external view returns (IEigenPodManager);

    /**
     * @notice Returns the EigenPod
     */
    function eigenPod() external view returns (IEigenPod);

    /**
     * @notice Sets the `podProxyowner` and `podRewardsRecipient`
     * @dev This can be consireder a 'second' initializer
     *      Only PufferPool is calling this once after the initialization.
     *      The reason for that is that we need to be able to predict EigenPodProxy's address, and upon BeaconProxy's creation in the constructor
     *      we are passing in the initializer data, because of that we want to get rid of the dynamic data from the initializer
     */
    function setPodProxyOwnerAndRewardsRecipient(address payable podProxyowner, address payable podRewardsRecipient)
        external;
    /**
     * @notice Initiated by the PufferPool. Calls stake() on the EigenPodManager to deposit Beacon Chain ETH and create another ETH validator
     */
    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot) external payable;
    /**
     * @notice Returns the pufETH bond to PodProxyOwner if they no longer want to stake
     * @param publicKeyHash is the keccak256 hash of the validator's public key
     */
    function stopRegistration(bytes32 publicKeyHash) external;
    /**
     * @notice Calls optIntoSlashing on the Slasher.sol() contract as part of the AVS registration process
     */
    function enableSlashing(address contractAddress) external;
    /**
     * @notice Register to generic AVS. Only callable by pod owner
     */
    function registerToAVS(bytes calldata registrationData) external;
    /**
     * @notice Register to Puffer AVS. Callable by anyone
     */
    function registerToPufferAVS(bytes calldata registrationData) external;

    /**
     * @notice Deregisters this EigenPodProxy from an AVS
     */
    function deregisterFromAVS() external;

    /**
     * @notice Updates the rewards recipient address. Callable only by Pod account.
     * @param podRewardsRecipient is the new rewards recipient
     */
    function updatePodRewardsRecipient(address payable podRewardsRecipient) external;

    /**
     * @notice Withdraws full EigenPod balance if corresponding validator was slashed before restaking
     */
    function withdrawSlashedEth() external;

    /**
     * @notice Calls verifyWithdrawalCredentialsAndBalance() on the owned EigenPod contract
     */
    function enableRestaking(
        uint64 oracleBlockNumber,
        uint40[] calldata validatorIndices,
        BeaconChainProofs.WithdrawalCredentialProofs[] calldata proofs,
        bytes32[][] calldata validatorFields
    ) external;

    // /**
    //  * TODO: natspec
    //  */
    // function verifyAndWithdraw(
    //     BeaconChainProofs.WithdrawalProofs[] calldata withdrawalProofs,
    //     bytes[] calldata validatorFieldsProofs,
    //     bytes32[][] calldata validatorFields,
    //     bytes32[][] calldata withdrawalFields,
    //     uint256 beaconChainETHStrategyIndex,
    //     uint64 oracleTimestamp
    // ) external;

    /**
     * @notice Completes an EigenPod's queued withdrawal by proving their beacon chain status
     */
    function completeWithdrawal() external;

    /**
     * @notice Releases `bondAmount` of pufETH to EigenPodProxy's owner
     * @dev Can only be called by PufferPool
     */
    function releaseBond(uint256 bondAmount) external;

    /**
     * @notice Returns the EigenPodProxy's owner
     */
    function getPodProxyOwner() external view returns (address payable);

    /**
     * @notice Returns the EigenPodProxy's manager which is PufferPool
     */
    function getPodProxyManager() external view returns (address payable);
}
