// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Initializable } from "openzeppelin/proxy/utils/Initializable.sol";
// Temporarily use a wrapper for EigenPod before eigenpodupdates branch is merged into eigenlayer contracts
import { IEigenPodWrapper } from "puffer/interface/IEigenPodWrapper.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { BeaconChainProofs } from "eigenlayer/libraries/BeaconChainProofs.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { SignedMath } from "openzeppelin/utils/math/SignedMath.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";

/**
 * @title EingenPodProxy
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 * @notice Eigen Pod Proxy is a contract that owns EigenPod and is responsible with interacting with it
 */
contract EigenPodProxy is IEigenPodProxy, Initializable {
    /**
     * @dev {Safe} EigenPod is the pod proxy owner
     */
    address payable internal _podProxyOwner;

    /**
     * @dev PufferPool is the pod proxy manager
     */
    IPufferPool internal _podProxyManager;

    /**
     * @dev The designated address to send pod rewards. Can be changed by podProxyOwner
     */
    address payable internal _podRewardsRecipient;

    /**
     * @dev Address of the Pod owned by this proxy
     */
    IEigenPodWrapper public ownedEigenPod;

    /**
     * @dev Upgradeable contract from EigenLayer
     */
    IEigenPodManager internal immutable _eigenPodManager;

    /**
     * @dev Upgradeable contract from EigenLayer
     */
    ISlasher internal immutable _slasher;

    // Keeps track of the previous status of the validator corresponding to this EigenPodProxy
    IEigenPodWrapper.VALIDATOR_STATUS internal _previousStatus;

    /**
     * @dev Bond amount
     */
    uint256 internal _bond;
    // Keeps track of any ETH owed to podOwner, but has not been paid due to slow withdrawal
    uint256 public owedToPodOwner;

    // Keeps track of addresses which AVS payments can be expected to come from
    mapping(address => bool) public AVSPaymentAddresses;

    bool public bondWithdrawn;
    bool public staked;

    constructor(IEigenPodManager eigenPodManager, ISlasher slasher) {
        _slasher = slasher;
        _eigenPodManager = eigenPodManager;
        _disableInitializers();
    }

    /// @notice Fallback function used to differentiate execution rewards from consensus rewards
    fallback() external payable {
        // If bond is already withdrawn, send any incoming money directly to pool
        if (bondWithdrawn) {
            _sendETH(payable(address(_podProxyManager)), msg.value);
            return;
        }
        if (AVSPaymentAddresses[msg.sender]) {
            _distributeAvsRewards(msg.value);
        } else if (msg.sender != address(ownedEigenPod)) {
            _distributeExecutionRewards(msg.value);
        } else {
            // TODO: Use the public key mapping to get the status of the corresponding validator
            IEigenPodWrapper.VALIDATOR_STATUS currentStatus = ownedEigenPod.validatorStatus(0);
            if (currentStatus == IEigenPodWrapper.VALIDATOR_STATUS.INACTIVE) {
                _handleInactiveSkim();
            } else if (currentStatus == IEigenPodWrapper.VALIDATOR_STATUS.ACTIVE) {
                _distributeConsensusRewards(msg.value);
            } else if (
                currentStatus == IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN
                    && _previousStatus == IEigenPodWrapper.VALIDATOR_STATUS.ACTIVE
            ) {
                _handleQuickWithdraw(msg.value);
            } else if (
                currentStatus == IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN
                    && _previousStatus == IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN
                    && ownedEigenPod.withdrawableRestakedExecutionLayerGwei() == 0
            ) {
                // Distribute all ETH upon full withdraw to Pool, podRewardsRecipient, and Treasury, burning pufETH
                _podProxyManager.withdrawFromProtocol{ value: address(this).balance }(
                    _podProxyManager.balanceOf(address(this)), _podRewardsRecipient, _bond
                );
                bondWithdrawn = true;
            }
        }
    }

    /// @notice Helper function to get the withdrawal credentials corresponding to the owned eigenPod
    function _getPodWithdrawalCredentials() internal view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(ownedEigenPod));
    }

    function getProxyManager() external view returns (address) {
        return address(_podProxyManager);
    }

    function initialize(address payable owner, IPufferPool manager, address payable podRewardsRecipient, uint256 bond)
        external
        initializer
    {
        _podRewardsRecipient = podRewardsRecipient;
        _bond = bond;
        _podProxyOwner = owner;
        _podProxyManager = manager;
        _previousStatus = IEigenPodWrapper.VALIDATOR_STATUS.INACTIVE;
        _eigenPodManager.createPod();
        ownedEigenPod = IEigenPodWrapper(address(_eigenPodManager.ownerToPod(address(this))));
    }

    modifier onlyPodProxyOwner() {
        if (msg.sender != _podProxyOwner) {
            revert Unauthorized();
        }
        _;
    }

    modifier onlyPodProxyManager() {
        if (msg.sender != address(_podProxyManager)) {
            revert Unauthorized();
        }
        _;
    }

    function _distributeFunds(uint256 total, uint256 toPod) internal {
        _sendETH(_podRewardsRecipient, toPod);
        _sendETH(getPodProxyManager(), total - toPod);
    }

    function _distributeAvsRewards(uint256 amount) internal {
        uint256 toPod = (amount * _podProxyManager.getAvsCommission()) / _podProxyManager.getCommissionDenominator();
        _distributeFunds(amount, toPod);
    }

    function _distributeExecutionRewards(uint256 amount) internal {
        uint256 toPod =
            (amount * _podProxyManager.getExecutionCommission()) / _podProxyManager.getCommissionDenominator();
        _distributeFunds(amount, toPod);
    }

    function _distributeConsensusRewards(uint256 amount) internal {
        uint256 toPod =
            (amount * _podProxyManager.getConsensusCommission()) / _podProxyManager.getCommissionDenominator();
        _distributeFunds(amount, toPod);
    }

    function _handleInactiveSkim() internal {
        _podProxyManager.withdrawFromProtocol{ value: address(this).balance }(
            _podProxyManager.balanceOf(address(this)), _podRewardsRecipient, _bond
        );
        bondWithdrawn = true;
    }

    function _handleQuickWithdraw(uint256 amount) internal {
        // Eth owned to podProxyOwner
        // Up to 1 ETH will remain on this contract until fullWithdrawal
        uint256 skimmable = SignedMath.abs(SignedMath.max(int256(amount - 1 ether), 0));
        uint256 podsCut =
            (skimmable * _podProxyManager.getConsensusCommission()) / _podProxyManager.getCommissionDenominator();
        _sendETH(_podRewardsRecipient, podsCut);

        // ETH owed to pool
        uint256 poolCut = skimmable - podsCut;
        _sendETH(getPodProxyManager(), poolCut);

        // Update previous status to withdrawn
        _previousStatus = IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN;
    }

    function updatePodRewardsRecipient(address payable podRewardsRecipient) external onlyPodProxyOwner {
        _podRewardsRecipient = podRewardsRecipient;
        // todo: missing event
    }

    /// @notice Initiated by the PufferPool. Calls stake() on the EigenPodManager to deposit Beacon Chain ETH and create another ETH validator
    function callStake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable
        onlyPodProxyManager
    {
        require(!bondWithdrawn, "The bond has been withdrawn, cannot stake");
        staked = true;
        _eigenPodManager.stake{ value: 32 ether }(pubkey, signature, depositDataRoot);
    }

    /// @notice Returns the pufETH bond to PodProxyOwner if they no longer want to stake
    function stopRegistraion() external onlyPodProxyOwner {
        require(!staked, "pufETH bond is locked, because pod is already staking");
        bondWithdrawn = true;
        _podProxyManager.transfer(_podRewardsRecipient, _podProxyManager.balanceOf(address(this)));
    }

    /// @notice Calls optIntoSlashing on the Slasher.sol() contract as part of the AVS registration process
    function enableSlashing(address contractAddress) external {
        // Note this contract address as potential payment address
        AVSPaymentAddresses[contractAddress] = true;
        _slasher.optIntoSlashing(contractAddress);
    }

    /// @notice Register to generic AVS. Only callable by pod owner
    function registerToAVS(bytes calldata registrationData) external { }

    /// @notice Register to Puffer AVS. Callable by anyone
    function registerToPufferAVS(bytes calldata registrationData) external { }

    /// @notice Deregisters this EigenPodProxy from an AVS
    function deregisterFromAVS() external { }

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
        _previousStatus = IEigenPodWrapper.VALIDATOR_STATUS.ACTIVE;
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

    /**
     * @inheritdoc IEigenPodProxy
     */
    function getPodProxyManager() public view returns (address payable) {
        return payable(address(_podProxyManager));
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function getPodProxyOwner() public view returns (address payable) {
        return payable(_podProxyOwner);
    }

    function _sendETH(address payable to, uint256 amount) internal {
        if (amount == 0) {
            return;
        }
        (bool sent, bytes memory data) = to.call{ value: amount }("");
        require(sent, "Failed to send Ether");
    }
}
