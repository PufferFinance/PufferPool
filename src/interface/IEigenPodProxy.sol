// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "eigenlayer/libraries/BeaconChainProofs.sol";
import "eigenlayer/interfaces/IEigenPodManager.sol";
import "eigenlayer/interfaces/IBeaconChainOracle.sol";
import "eigenlayer/interfaces/IEigenPod.sol";

interface IEigenPodProxy {
    /// @notice The amount of eth, in gwei, that is restaked per validator
    function REQUIRED_BALANCE_GWEI() external view returns(uint64);

    /// @notice The amount of eth, in wei, that is restaked per validator
    function REQUIRED_BALANCE_WEI() external view returns(uint256);

    /// @notice this is a mapping of validator indices to a Validator struct containing pertinent info about the validator
    function validatorStatus(uint40 validatorIndex) external view returns(IEigenPod.VALIDATOR_STATUS);

    /// @notice the amount of execution layer ETH in this contract that is staked in EigenLayer (i.e. withdrawn from beaconchain but not EigenLayer), 
    function restakedExecutionLayerGwei() external view returns(uint64);

    /// @notice The single EigenPodManager for EigenLayer
    function eigenPodManager() external view returns (IEigenPodManager);

    /// @notice The PufferPool will act as the PodManager via this EigenPodProxy
    function podProxyManager() external view returns (address);

    /// @notice A PodAccount will act as the PodOwner via this EigenPodProxy
    function podProxyOwner() external view returns (address);

    /// @notice The Eigenpod owned by this EigenPodProxy contract
    function ownedEigenPod() external view returns (address);

    /// @notice an indicator of whether or not the podOwner has ever "fully restaked" by successfully calling `verifyCorrectWithdrawalCredentials`.
    function hasRestaked() external view returns (bool);

    /// @notice block number of the most recent withdrawal
    function mostRecentWithdrawalBlockNumber() external view returns (uint64);

    /// @notice Used to initialize the pointers to contracts crucial to the pod's functionality, in beacon proxy construction from EigenPodManager
    function initialize(address owner) external;

    /// @notice Initiated by the PufferPool. Calls stake() on the EigenPodManager to deposit Beacon Chain ETH and create another ETH validator
    function callStake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable;

    /// @notice Calls optIntoSlashing on the Slasher.sol() contract as part of the AVS registration process
    function enableSlashing(address contractAddress) external;

    /**
     * @notice Register AVS with Puffer Registry
     */
    function registerToAVS(bytes calldata registrationData) external;

    /// @notice Called by PufferPool and PodAccount to distribute ETH funds among PufferPool, PodAccount and Puffer Treasury
    function skim() external;

    /**
     * @notice This function records an overcommitment of stake to EigenLayer on behalf of a certain ETH validator.
     *         If successful, the overcommitted balance is penalized (available for withdrawal whenever the pod's balance allows).
     *         The ETH validator's shares in the enshrined beaconChainETH strategy are also removed from the StrategyManager and undelegated.
     * @param oracleBlockNumber The oracleBlockNumber whose state root the `proof` will be proven against.
     *        Must be within `VERIFY_OVERCOMMITTED_WINDOW_BLOCKS` of the current block.
     * @param validatorIndex is the index of the validator being proven, refer to consensus specs 
     * @param proofs is the proof of the validator's balance and validatorFields in the balance tree and the balanceRoot to prove for
     * @param beaconChainETHStrategyIndex is the index of the beaconChainETHStrategy for the pod owner for the callback to 
     *                                    the StrategyManager in case it must be removed from the list of the podOwners strategies
     * @param validatorFields are the fields of the "Validator Container", refer to consensus specs
     * @dev For more details on the Beacon Chain spec, see: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
     */
    function verifyOvercommittedStake(
        uint40 validatorIndex,
        BeaconChainProofs.ValidatorFieldsAndBalanceProofs calldata proofs,
        bytes32[] calldata validatorFields,
        uint256 beaconChainETHStrategyIndex,
        uint64 oracleBlockNumber
    ) external;

    ///@notice mapping that tracks proven partial withdrawals
    function provenPartialWithdrawal(uint40 validatorIndex, uint64 slot) external view returns (bool);

    /**
     * @notice Called by a staker to queue a withdrawal of the given amount of `shares` from each of the respective given `strategies`.
     * @dev Stakers will complete their withdrawal by calling the 'completeQueuedWithdrawal' function.
     * User shares are decreased in this function, but the total number of shares in each strategy remains the same.
     * The total number of shares is decremented in the 'completeQueuedWithdrawal' function instead, which is where
     * the funds are actually sent to the user through use of the strategies' 'withdrawal' function. This ensures
     * that the value per share reported by each strategy will remain consistent, and that the shares will continue
     * to accrue gains during the enforced withdrawal waiting period.
     * @param strategyIndexes is a list of the indices in `stakerStrategyList[msg.sender]` that correspond to the strategies
     * for which `msg.sender` is withdrawing 100% of their shares
     * @param strategies The Strategies to withdraw from
     * @param shares The amount of shares to withdraw from each of the respective Strategies in the `strategies` array
     * @param withdrawer The address that can complete the withdrawal and will receive any withdrawn funds or shares upon completing the withdrawal
     * @param undelegateIfPossible If this param is marked as 'true' *and the withdrawal will result in `msg.sender` having no shares in any Strategy,*
     * then this function will also make an internal call to `undelegate(msg.sender)` to undelegate the `msg.sender`.
     * @dev Strategies are removed from `stakerStrategyList` by swapping the last entry with the entry to be removed, then
     * popping off the last entry in `stakerStrategyList`. The simplest way to calculate the correct `strategyIndexes` to input
     * is to order the strategies *for which `msg.sender` is withdrawing 100% of their shares* from highest index in
     * `stakerStrategyList` to lowest index
     * @dev Note that if the withdrawal includes shares in the enshrined 'beaconChainETH' strategy, then it must *only* include shares in this strategy, and
     * `withdrawer` must match the caller's address. The first condition is because slashing of queued withdrawals cannot be guaranteed 
     * for Beacon Chain ETH (since we cannot trigger a withdrawal from the beacon chain through a smart contract) and the second condition is because shares in
     * the enshrined 'beaconChainETH' strategy technically represent non-fungible positions (deposits to the Beacon Chain, each pointed at a specific EigenPod).
     */
    function queueWithdrawal(
        uint256[] calldata strategyIndexes,
        IStrategy[] calldata strategies,
        uint256[] calldata shares,
        address withdrawer,
        bool undelegateIfPossible
    )
        external;

    /**
     * @notice Transfers `amountWei` in ether from this contract to the specified `recipient` address
     * @notice Called by EigenPodManager to withdrawBeaconChainETH that has been added to the EigenPod's balance due to a withdrawal from the beacon chain.
     * @dev Called during withdrawal or slashing.
     * @dev Note that this function is marked as non-reentrant to prevent the recipient calling back into it
     */
    function withdrawRestakedBeaconChainETH(address recipient, uint256 amount) external;
    

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
    function verifyAndProcessWithdrawal(
        BeaconChainProofs.WithdrawalProofs calldata withdrawalProofs, 
        bytes calldata validatorFieldsProof,
        bytes32[] calldata validatorFields,
        bytes32[] calldata withdrawalFields,
        uint256 beaconChainETHStrategyIndex,
        uint64 oracleBlockNumber
    ) external;

    /// @notice Called by the pod owner to withdraw the balance of the pod when `hasRestaked` is set to false
    function withdrawBeforeRestaking() external;
}