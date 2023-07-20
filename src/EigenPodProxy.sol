// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Initializable } from "openzeppelin/proxy/utils/Initializable.sol";
import "openzeppelin/token/ERC20/IERC20.sol";
import "openzeppelin/utils/math/Math.sol";
import "./interface/IEigenPodProxy.sol";
import "./interface/IPufferPool.sol";
// Temporarily use a wrapper for EigenPod before eigenpodupdates branch is merged into eigenlayer contracts
import "./interface/IEigenPodWrapper.sol";
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
    // The designated address to send pod rewards. Can be changed by podProxyOwner
    address payable public podRewardsRecipient;

    IERC20 pufETH;

    IEigenPodWrapper public ownedEigenPod;
    // EigenLayer's Singular EigenPodManager contract
    IEigenPodManager public eigenPodManager;
    // EigenLayer's Singular Slasher contract
    ISlasher public slasher;
    // The Singular PufferPool contract
    IPufferPool public pufferPool;
    // Keeps track of the previous status of the validator corresponding to this EigenPodProxy
    IEigenPodWrapper.VALIDATOR_STATUS previousStatus;

    // Bond amount
    uint8 bond;
    // Keeps track of any ETH owed to podOwner, but has not been paid due to slow withdrawal
    uint256 public owedToPodOwner;

    // TODO: Should these be defined elsewhere so that all eigenPods can (more conveniently) have consistent behavior?
    // Number of shares out of one billion to split AVS rewards with the pool
    uint256 podAVSCommission;
    //Number of shares out of one billion to split consensus rewards with the pool
    uint256 consensusRewardsSplit;
    //Number of shares out of one billion to split execution rewards with the pool
    uint256 executionRewardsSplit;

    // Keeps track of how much eth was withdrawn from the EigenPod
    uint256 withdrawnETH;

    // Keeps track of addresses which AVS payments can be expected to come from
    mapping(address => bool) public AVSPaymentAddresses;

    bool public bondWithdrawn;
    bool public staked;

    constructor(
        address payable _podProxyOwner,
        address payable _podProxyManager,
        address payable _pufferPool,
        address payable _podRewardsRecipient,
        address _slasher,
        address _pufETH,
        address _eigenPodManager,
        uint256 _podAVSCommission,
        uint256 _consensusRewardsSplit,
        uint256 _executionRewardsSplit,
        uint8 _bond
    ) {
        // _manager = manager;
        podProxyOwner = _podProxyOwner;
        podProxyManager = _podProxyManager;
        eigenPodManager = IEigenPodManager(_eigenPodManager);
        slasher = ISlasher(_slasher);
        pufferPool = IPufferPool(_pufferPool);
        pufETH = IERC20(_pufETH);

        podRewardsRecipient = _podRewardsRecipient;

        podAVSCommission = _podAVSCommission;
        consensusRewardsSplit = _consensusRewardsSplit;
        executionRewardsSplit = _executionRewardsSplit;

        bond = _bond;

        previousStatus = IEigenPodWrapper.VALIDATOR_STATUS.INACTIVE;
    }

    /// @notice Fallback function used to differentiate execution rewards from consensus rewards
    fallback() external payable {
        if (AVSPaymentAddresses[msg.sender]) {
            _sendETH(podRewardsRecipient, (msg.value * podAVSCommission) / 10 ** 9);
            _sendETH(podProxyManager, address(this).balance);
        } else if (msg.sender != address(ownedEigenPod)) {
            _sendETH(podRewardsRecipient, (msg.value * executionRewardsSplit) / 10 ** 9);
            _sendETH(podProxyManager, address(this).balance);
        } else {
            // TODO: Use the public key mapping to get the status of the corresponding validator
            IEigenPodWrapper.VALIDATOR_STATUS currentStatus = ownedEigenPod.validatorStatus(0);
            if (
                msg.sender == address(ownedEigenPod) && currentStatus == IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN
                    && previousStatus == IEigenPodWrapper.VALIDATOR_STATUS.ACTIVE
            ) {
                // Eth owned to podProxyOwner
                uint256 skimmable = Math.max(msg.value - 1 ether, 0);
                uint256 podsCut = skimmable * consensusRewardsSplit;
                uint256 podRewards = podsCut + (address(this).balance - skimmable) * consensusRewardsSplit;
                _sendETH(podRewardsRecipient, podRewards);

                // ETH to be returned later (not taxed by treasury)
                withdrawnETH = msg.value - skimmable;

                // ETH owed to pool
                uint256 poolCut = address(this).balance - withdrawnETH;
                _sendETH(podProxyManager, poolCut);

                // Update previous status to this current status
                previousStatus = currentStatus;
            } else if (
                msg.sender == address(ownedEigenPod) && currentStatus == IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN
                    && previousStatus == IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN
                    && ownedEigenPod.withdrawableRestakedExecutionLayerGwei() == 0
            ) {
                withdrawnETH += msg.value;
                int256 debt = int256(32 ether - bond - withdrawnETH);

                // Handle any rewards
                uint256 skimmable = address(this).balance - withdrawnETH;

                if (debt <= 0) {
                    // ETH owed to podProxyOwner
                    uint256 podRewards = Math.max(skimmable, 0) * consensusRewardsSplit;
                    _sendETH(podRewardsRecipient, podRewards);

                    // ETH owed to pool
                    uint256 poolRewards = skimmable - podRewards;
                    _sendETH(podProxyManager, poolRewards);

                    // Return up to 2 ETH bond back to PodProxyOwner and burn this contract's pufEth
                    _sendETH(podRewardsRecipient, Math.max(withdrawnETH - (32 ether - bond), 0));
                    pufferPool.burnAndNoWithdraw();
                }

                // Return remained to the pool (not taxed by treasury)
                pufferPool.returnETH(address(this).balance);
            }
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

    modifier onlyPodProxyOwner() {
        if (msg.sender != podProxyOwner) {
            revert Unauthorized();
        }
        _;
    }

    function updatePodRewardsRecipient(address payable _podRewardsRecipient) external onlyPodProxyOwner {
        podRewardsRecipient = _podRewardsRecipient;
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
        ownedEigenPod = IEigenPodWrapper(address(eigenPodManager.ownerToPod(address(this))));
    }

    /// @notice Initiated by the PufferPool. Calls stake() on the EigenPodManager to deposit Beacon Chain ETH and create another ETH validator
    function callStake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable {
        require(!bondWithdrawn, "The bond has been withdrawn, cannot stake");
        require(msg.sender == podProxyManager, "Only podProxyManager allowed");
        require(msg.value == 32 ether, "Must be called with 32 ETH");
        eigenPodManager.stake{ value: 32 ether }(pubkey, signature, depositDataRoot);
        staked = true;
    }

    /// @notice Withdraws full EigenPod balance if they've never restaked
    function earlyWithdraw() external payable {
        require(msg.sender == podProxyOwner, "Only podProxyOwner allowed");
        ownedEigenPod.withdrawBeforeRestaking();
    }

    /// @notice Returns the pufETH bond to PodProxyOwner if they no longer want to stake
    function stopRegistraion() external onlyPodProxyOwner {
        require(!staked, "pufETH bond is locked, because pod is already staking");
        bondWithdrawn = true;
        pufETH.transfer(podRewardsRecipient, pufETH.balanceOf(address(this)));
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
        IEigenPodWrapper.VALIDATOR_STATUS status = ownedEigenPod.validatorStatus(0);
        uint256 contractBalance = address(this).balance;

        require(
            status != IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN
                && status != IEigenPodWrapper.VALIDATOR_STATUS.OVERCOMMITTED,
            "Can't be withdrawn or overcommitted"
        );
        require(contractBalance > 0 || owedToPodOwner > 0, "No ETH to skim");

        // TODO: Revisit the inactive case later
        if (status == IEigenPodWrapper.VALIDATOR_STATUS.INACTIVE) {
            if (contractBalance >= 32 ether) {
                _sendETH(
                    podRewardsRecipient,
                    bond + ((contractBalance - (32 ether - bond)) * consensusRewardsSplit) / 10 ** 9
                );
                _sendETH(podProxyManager, address(this).balance);
            } else {
                _sendETH(podRewardsRecipient, Math.max(contractBalance - (32 ether - bond), 0));
                _sendETH(podProxyManager, address(this).balance);
            }
        } else if (status == IEigenPodWrapper.VALIDATOR_STATUS.ACTIVE) {
            _sendETH(podRewardsRecipient, (contractBalance * consensusRewardsSplit) / 10 ** 9);
            _sendETH(podProxyManager, address(this).balance);
        }
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
        previousStatus = IEigenPodWrapper.VALIDATOR_STATUS.ACTIVE;
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
