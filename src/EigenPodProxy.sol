// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Initializable } from "openzeppelin/proxy/utils/Initializable.sol";
import "openzeppelin/utils/math/Math.sol";
import "./interface/IEigenPodProxy.sol";
import "eigenlayer/interfaces/IEigenPod.sol";
import "eigenlayer/interfaces/ISlasher.sol";

/**
 * @title EingenPodProxy
 * @author Puffer finance
 * @notice TODO: interacts with EigenLayer
 */
contract EigenPodProxy is Initializable, IEigenPodProxy {
    /**
     * @dev Thrown if the msg.sender is unauthorized.
     */
    error Unauthorized();

    // TODO: getters, OZ ownable and/or access control
    address internal _owner;
    address internal _manager;
    // PodAccount
    address payable public podProxyOwner;
    // PufferPool
    address payable public podProxyManager;

    IEigenPod public ownedEigenPod;
    // EigenLayer's Singular EigenPodManager contract
    IEigenPodManager public eigenPodManager;
    // EigenLayer's Slasher contract
    ISlasher public slasher;
    // Keeps track of the previous status of the validator corresponding to this EigenPodProxy
    IEigenPod.VALIDATOR_STATUS previousStatus;

    // Keeps track of any ETH owed to podOwner, but has not been paid due to slow withdrawal
    uint256 public owedToPodOwner;
    // Keeps track of AVS rewards received
    uint256 public AVSRewards;
    // If ETH hits this contract, and not from the ownedEigenPod contract, or AVS, consider it execution rewards
    uint256 public executionRewards;

    // TODO: Should these be defined elsewhere so that all eigenPods can (more conveniently) have consistent behavior?
    // Number of shares out of one billion to split AVS rewards with the pool
    uint256 podAVSCommission;
    //Number of shares out of one billion to split consensus rewards with the pool
    uint256 consensusRewardsSplit;
    //Number of shares out of one billion to split execution rewards with the pool
    uint256 executionRewardsSplit;

    // Keeps track of addresses which AVS payments can be expected to come from
    mapping(address => bool) public AVSPaymentAddresses;

    constructor(
        address payable _podProxyOwner,
        address payable _podProxyManager,
        address _slasher,
        address _eigenPodManager,
        uint256 _podAVSCommission,
        uint256 _consensusRewardsSplit,
        uint256 _executionRewardsSplit
    ) {
        // _manager = manager;
        podProxyOwner = _podProxyOwner;
        podProxyManager = _podProxyManager;
        eigenPodManager = IEigenPodManager(_eigenPodManager);
        slasher = ISlasher(_slasher);

        podAVSCommission = _podAVSCommission;
        consensusRewardsSplit = _consensusRewardsSplit;
        executionRewardsSplit = _executionRewardsSplit;

        previousStatus = IEigenPod.VALIDATOR_STATUS.INACTIVE;
    }

    /// @notice Fallback function used to differentiate execution rewards from consensus rewards
    fallback() external payable {
        if (AVSPaymentAddresses[msg.sender]) {
            AVSRewards += msg.value;
        } else if (msg.sender != address(ownedEigenPod)) {
            executionRewards += msg.value;
        }
    }

    /// @notice Helper function to get the withdrawal credentials corresponding to the owned eigenPod
    function _getPodWithdrawalCredentials() internal view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(ownedEigenPod));
    }

    function getManager() external view returns (address) {
        return _manager;
    }

    function initialize(address owner, address manager) external initializer {
        _owner = owner;
        _manager = manager;
    }

    modifier onlyOwner() {
        if (msg.sender != _owner) {
            revert Unauthorized();
        }
        _;
    }

    modifier onlyManager() {
        if (msg.sender != _manager) {
            revert Unauthorized();
        }
        _;
    }

    function eigenStake() external onlyManager {
        // TODO:
    }

    /// @notice Creates an EigenPod without depositiing ETH
    function createEmptyPod() external {
        require(tx.origin == podProxyOwner, "Only PodProxyOwner allowed");
        require(address(ownedEigenPod) == address(0), "Must not have instantiated EigenPod");

        eigenPodManager.createPod();

        // This contract is the owner of the created eigenPod
        ownedEigenPod = eigenPodManager.ownerToPod(address(this));
    }

    /// @notice Initiated by the PufferPool. Calls stake() on the EigenPodManager to deposit Beacon Chain ETH and create another ETH validator
    function callStake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable {
        require(msg.sender == podProxyManager, "Only podProxyManager allowed");
        require(msg.value == 32 ether, "Must be called with 32 ETH");
        eigenPodManager.stake{ value: 32 ether }(pubkey, signature, depositDataRoot);
    }

    /// @notice Withdraws full EigenPod balance if they've never restaked
    function earlyWithdraw() external payable {
        require(msg.sender == podProxyOwner, "Only podProxyOwner allowed");
        ownedEigenPod.withdrawBeforeRestaking();
    }

    /// @notice Calls optIntoSlashing on the Slasher.sol() contract as part of the AVS registration process
    function enableSlashing(address contractAddress) external {
        // Note this contract address as potential payment address
        AVSPaymentAddresses[contractAddress] = true;
        slasher.optIntoSlashing(contractAddress);
    }

    /// @notice Register to generic AVS. Only callable by pod owner
    function registerToAVS(bytes calldata registrationData) external { }

    /// @notice Register to Puffer AVS. Callable by anyone
    function registerToPufferAVS(bytes calldata registrationData) external { }

    /// @notice Deregisters this EigenPodProxy from an AVS
    function deregisterFromAVS() external { }

    /// @notice Called by PufferPool and PodAccount to distribute ETH funds among PufferPool, PodAccount and Puffer Treasury
    function skim() external {
        // TODO: Use the public key mapping to get the status of the corresponding validator
        IEigenPod.VALIDATOR_STATUS status = ownedEigenPod.validatorStatus(0);
        uint256 contractBalance = address(this).balance;

        require(
            status != IEigenPod.VALIDATOR_STATUS.WITHDRAWN && status != IEigenPod.VALIDATOR_STATUS.OVERCOMMITTED,
            "Can't be withdrawn or overcommitted"
        );
        require(contractBalance > 0 || owedToPodOwner > 0, "No ETH to skim");

        // TODO: Revisit the inactive case later
        if (status == IEigenPod.VALIDATOR_STATUS.INACTIVE) {
            if (contractBalance >= 32 ether) {
                _sendETH(podProxyOwner, 2 ether + ((contractBalance - 30 ether) * podAVSCommission) / 10 ** 9);
                _sendETH(podProxyManager, address(this).balance);
            } else {
                _sendETH(podProxyOwner, Math.max(contractBalance - 30 ether, 0));
                _sendETH(podProxyManager, address(this).balance);
            }
            // Reset execution rewards and AVS rewards because we just withdrew all ETH
            executionRewards = 0;
            AVSRewards = 0;
        } else if (status == IEigenPod.VALIDATOR_STATUS.ACTIVE) {
            _sendETH(
                podProxyOwner,
                (
                    (contractBalance - executionRewards - AVSRewards) * consensusRewardsSplit
                        + executionRewards * executionRewardsSplit + AVSRewards * podAVSCommission
                ) / 10 ** 9
            );
            _sendETH(podProxyManager, address(this).balance);
            // Reset execution and AVS rewards after skimming
            executionRewards = 0;
            AVSRewards = 0;
        } else if (status == IEigenPod.VALIDATOR_STATUS.WITHDRAWN) { }
    }

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
    function initiateWithdrawal(uint256[] calldata shares) external { }

    /// @notice Calls verifyWithdrawalCredentialsAndBalance() on the owned EigenPod contract
    function enableRestaking(
        uint64 oracleBlockNumber,
        uint40 validatorIndex,
        BeaconChainProofs.ValidatorFieldsAndBalanceProofs memory proofs,
        bytes32[] calldata validatorFields
    ) external {
        ownedEigenPod.verifyWithdrawalCredentialsAndBalance(oracleBlockNumber, validatorIndex, proofs, validatorFields);
        // Keep track of ValidatorStatus state changes
        previousStatus = IEigenPod.VALIDATOR_STATUS.ACTIVE;
    }

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
    ) external { }

    /// @notice Completes an EigenPod's queued withdrawal by proving their beacon chain status
    function completeWithdrawal() external { }

    function _sendETH(address payable to, uint256 amount) internal {
        (bool sent, bytes memory data) = to.call{ value: amount }("");
        require(sent, "Failed to send Ether");
    }
}