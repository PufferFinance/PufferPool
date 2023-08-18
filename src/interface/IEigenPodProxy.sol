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
     * @param manager is the Manager of Eigen Pod Proxy (PufferPool)
     * @param bond is the bond amount
     */
    function initialize(IPufferPool manager, uint256 bond) external;

    /**
     * @notice Returns the Eigen pod manager from EigenLayer
     */
    function getEigenPodManager() external view returns (IEigenPodManager);

    /**
     * @notice Returns the EigenPod
     */
    function ownedEigenPod() external view returns (IEigenPod);

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
     * @notice Called by a staker to queue a withdrawal of the given amount of `shares` from each of the respective given `strategies`.
     * @dev Stakers will complete their withdrawal by calling the 'completeQueuedWithdrawal' function.
     * User shares are decreased in this function, but the total number of shares in each strategy remains the same.
     * The total number of shares is decremented in the 'completeQueuedWithdrawal' function instead, which is where
     * the funds are actually sent to the user through use of the strategies' 'withdrawal' function. This ensures
     * that the value per share reported by each strategy will remain consistent, and that the shares will continue
     * to accrue gains during the enforced withdrawal waiting period.
     * @dev Note that if the withdrawal includes shares in the enshrined 'beaconChainETH' strategy, then it must *only* include shares in this strategy, and
     * `withdrawer` must match the caller's address. The first condition is because slashing of queued withdrawals cannot be guaranteed
     * for Beacon Chain ETH (since we cannot trigger a withdrawal from the beacon chain through a smart contract) and the second condition is because shares in
     * the enshrined 'beaconChainETH' strategy technically represent non-fungible positions (deposits to the Beacon Chain, each pointed at a specific EigenPod).
     */
    function initiateWithdrawal() external;

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

    /**
     * @notice This function records a full withdrawal on behalf of one of the Ethereum validators for this EigenPod
     * @param withdrawalProofs is the information needed to check the veracity of the block number and withdrawal being proven
     * @param validatorFieldsProof is the proof of the validator's fields in the validator tree
     * @param withdrawalFields are the fields of the withdrawal being proven
     * @param validatorFields are the fields of the validator being proven
     * @param beaconChainETHStrategyIndex is the index of the beaconChainETHStrategy for the pod owner for the callback to
     *        the EigenPodManager to the StrategyManager in case it must be removed from the podOwner's list of strategies
     */
    function verifyAndWithdraw(
        BeaconChainProofs.WithdrawalProofs calldata withdrawalProofs,
        bytes calldata validatorFieldsProof,
        bytes32[] calldata validatorFields,
        bytes32[] calldata withdrawalFields,
        uint256 beaconChainETHStrategyIndex,
        uint64 oracleBlockNumber
    ) external;

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
