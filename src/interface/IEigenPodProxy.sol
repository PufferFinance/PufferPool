// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "eigenlayer/libraries/BeaconChainProofs.sol";
import "eigenlayer/interfaces/IEigenPodManager.sol";

interface IEigenPodProxy {
    /// @notice The single EigenPodManager for EigenLayer
    function eigenPodManager() external view returns (IEigenPodManager);

    /// @notice The PufferPool will act as the PodManager via this EigenPodProxy
    function podProxyManager() external view returns (address);

    /// @notice A PodAccount will act as the PodOwner via this EigenPodProxy
    function podProxyOwner() external view returns (address);

    /// @notice The Eigenpod owned by this EigenPodProxy contract
    function ownedEigenPod() external view returns (address);

    /// @notice Initiated by the PufferPool. Calls stake() on the EigenPodManager to deposit Beacon Chain ETH and create another ETH validator
    function callStake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable;

    /// @notice Calls optIntoSlashing on the Slasher.sol() contract as part of the AVS registration process
    function enableSlashing(address contractAddress) external;

    /// @notice Register to generic AVS. Only callable by pod owner
    function registerToAVS(bytes calldata registrationData) external;

    /// @notice Register to Puffer AVS. Callable by anyone
    function registerToPufferAVS(bytes calldata registrationData) external;

    /// @notice Called by PufferPool and PodAccount to distribute ETH funds among PufferPool, PodAccount and Puffer Treasury
    function skim() external;

    /**
     * @notice Called by a staker to queue a withdrawal of the given amount of `shares` from each of the respective given `strategies`.
     * @dev Stakers will complete their withdrawal by calling the 'completeQueuedWithdrawal' function.
     * User shares are decreased in this function, but the total number of shares in each strategy remains the same.
     * The total number of shares is decremented in the 'completeQueuedWithdrawal' function instead, which is where
     * the funds are actually sent to the user through use of the strategies' 'withdrawal' function. This ensures
     * that the value per share reported by each strategy will remain consistent, and that the shares will continue
     * to accrue gains during the enforced withdrawal waiting period.
     * @param shares The amount of shares to withdraw from each of the respective Strategies in the `strategies` array
     * @dev Note that if the withdrawal includes shares in the enshrined 'beaconChainETH' strategy, then it must *only* include shares in this strategy, and
     * `withdrawer` must match the caller's address. The first condition is because slashing of queued withdrawals cannot be guaranteed 
     * for Beacon Chain ETH (since we cannot trigger a withdrawal from the beacon chain through a smart contract) and the second condition is because shares in
     * the enshrined 'beaconChainETH' strategy technically represent non-fungible positions (deposits to the Beacon Chain, each pointed at a specific EigenPod).
     */
    function initiateWithdrawal(uint256[] calldata shares) external;

    /// @notice Calls verifyWithdrawalCredentialsAndBalance() on the owned EigenPod contract
    function enableRestaking(
        uint64 oracleBlockNumber,
        uint40 validatorIndex,
        BeaconChainProofs.ValidatorFieldsAndBalanceProofs memory proofs,
        bytes32[] calldata validatorFields
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
}