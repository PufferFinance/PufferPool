// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Initializable } from "openzeppelin/proxy/utils/Initializable.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";
import { IDelayedWithdrawalRouter } from "eigenlayer/interfaces/IDelayedWithdrawalRouter.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { BeaconChainProofs } from "eigenlayer/libraries/BeaconChainProofs.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { Endian } from "eigenlayer/libraries/Endian.sol";

/**
 * @title EingenPodProxy
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 * @notice Eigen Pod Proxy is a contract that owns EigenPod and is responsible with interacting with it
 */
contract EigenPodProxy is IEigenPodProxy, Initializable {
    /**
     * @dev Constant representing 100%
     */
    uint256 internal constant _ONE_HUNDRED_WAD = 100 * FixedPointMathLib.WAD;

    /**
     * @dev {Safe} PodAccount is the pod proxy owner
     */
    address payable internal _podProxyOwner;

    /**
     * @dev PufferPool is the pod proxy manager
     */
    IPufferPool internal _pool;

    /**
     * @dev The designated address to send pod rewards. Can be changed by podProxyOwner(PodAccount)
     */
    address payable internal _podRewardsRecipient;

    /**
     * @dev Address of the Pod owned by this proxy
     */
    IEigenPod public eigenPod;

    /**
     * @dev Upgradeable contract from EigenLayer
     */
    IEigenPodManager internal immutable _eigenPodManager;

    /**
     * @dev Upgradeable contract from EigenLayer
     */
    ISlasher internal immutable _slasher;

    /**
     * @dev Counter of how many withdrawals from the delayed router we've processed
     */
    uint256 internal _withdrawalsProcessed;

    // Keeps track of the previous status of the validator corresponding to this EigenPodProxy
    IEigenPod.VALIDATOR_STATUS internal _previousStatus;

    /**
     * @dev Keeps track of important data for validators related to the owned EigenPod
     */
    ValidatorData[] validatorData;

    /**
     * @dev Mapping representing the full withdrawals
     */
    mapping(uint256 index => uint256 validatorBond) internal _fullWithdrawals;

    // Keeps track of addresses which AVS payments can be expected to come from
    mapping(address => bool) public AVSPaymentAddresses;

    modifier onlyPodProxyOwner() {
        if (msg.sender != _podProxyOwner) {
            revert Unauthorized();
        }
        _;
    }

    modifier onlyPodProxyManager() {
        if (msg.sender != address(_pool)) {
            revert Unauthorized();
        }
        _;
    }

    /**
     * @dev Pod owner and PufferPool are allowed
     */
    modifier onlyOwnerAndManager() {
        if (msg.sender != _podProxyOwner && msg.sender != address(_pool)) {
            revert Unauthorized();
        }
        _;
    }

    constructor(IEigenPodManager eigenPodManager, ISlasher slasher) {
        _slasher = slasher;
        _eigenPodManager = eigenPodManager;
        _disableInitializers();
    }

    function initialize(IPufferPool pool) external initializer {
        _pool = pool;
        _eigenPodManager.createPod();
        eigenPod = IEigenPod(address(_eigenPodManager.ownerToPod(address(this))));
    }

    /// @notice Fallback function used to differentiate execution rewards from consensus rewards
    receive() external payable {
        // TODO: Create a wrapper interface, or leave it like this?
        (, bytes memory data) = address(eigenPod).call(abi.encodeWithSignature("delayedWithdrawalRouter()"));
        address router = abi.decode(data, (address));
        // Everything that is not from the EigenLayer's router is execution reward / donation
        if (msg.sender != router) {
            return _distributeRewards(msg.value, _pool.getExecutionCommission());
        }

        // If we're here, that means that the msg.sender is the EigenLayer's router

        // Store idex to memory
        uint256 withdrawalIndex = _withdrawalsProcessed;

        // Increase the index
        _withdrawalsProcessed++;

        // Full withdrawals means that the validator decided to stop operating
        // bond is the pufETH amount
        uint256 bond = _fullWithdrawals[withdrawalIndex];
        if (bond != 0) {
            return _handleFullWithdrawal(bond);
        }

        // If it is not a full withdrawal, its is a consensus rewards withdrawal
        // Consensus rewards
        _distributeRewards(msg.value, _pool.getConsensusCommission());
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function getEigenPodManager() external view returns (IEigenPodManager) {
        return _eigenPodManager;
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function setPodProxyOwnerAndRewardsRecipient(address payable podProxyowner, address payable podRewardsRecipient)
        external
        onlyPodProxyManager
    {
        // Revert if the pod is already initialized
        if (_podProxyOwner != address(0)) {
            revert();
        }
        _podProxyOwner = podProxyowner;
        _setPodRewardsRecipient(podRewardsRecipient);
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function updatePodRewardsRecipient(address payable podRewardsRecipient) external onlyPodProxyOwner {
        _setPodRewardsRecipient(podRewardsRecipient);
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable
        onlyPodProxyManager
    {
        _eigenPodManager.stake{ value: 32 ether }(pubKey, signature, depositDataRoot);
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function stopRegistration(bytes32 publicKeyHash) external onlyPodProxyOwner {
        _pool.stopRegistration(publicKeyHash);
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function releaseBond(uint256 bondAmount) external onlyPodProxyManager {
        _pool.transfer(_podRewardsRecipient, bondAmount);
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function enableSlashing(address contractAddress) external {
        if (contractAddress != _pool.getPufferAvsAddress()) {
            require(msg.sender == _podProxyOwner, "Only PodProxyOwner can register to non Puffer AVS");
        }
        if (!_pool.isAVSEnabled(contractAddress)) {
            revert AVSNotSupported();
        }

        // Note this contract address as potential payment address
        AVSPaymentAddresses[contractAddress] = true;
        _slasher.optIntoSlashing(contractAddress);
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function registerToAVS(bytes calldata registrationData) external { }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function registerToPufferAVS(bytes calldata registrationData) external { }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function deregisterFromAVS() external { }

    /**
     * @notice Skims the rewards if EigenPod is not restaking.
     * @dev That means that we're doing native validation duties via EigenLayer, but we aren't restaking.
     *      On EigenLayer it takes any ETH balance sitting in EigenPod and queues it for this contract via EigenLayer's router
     *      To finalize Withdrawal we must call `router.claimDelayedWithdrawals(eigenPod)`
     */
    function skimRewards() external {
        // TODO: it can be DOS'ed if it is not protected, as it pushes an item to array on EigenLayer
        // TODO: make it callable 1x weekly callable by everybody, or make it onlyOwner
        eigenPod.withdrawBeforeRestaking();
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function withdrawSlashedEth() external { }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function enableRestaking(
        uint64 oracleBlockNumber,
        bytes32 pubKeyHash,
        uint40[] calldata validatorIndices,
        BeaconChainProofs.WithdrawalCredentialProofs[] calldata proofs,
        bytes32[][] calldata validatorFields
    ) external {
        uint64 previousRestakedBalanceGwei = eigenPod.validatorPubkeyHashToInfo(pubKeyHash).restakedBalanceGwei;
        eigenPod.verifyWithdrawalCredentials(oracleBlockNumber, validatorIndices, proofs, validatorFields);
        uint64 restakedBalanceGwei = eigenPod.validatorPubkeyHashToInfo(pubKeyHash).restakedBalanceGwei;
        require(restakedBalanceGwei > previousRestakedBalanceGwei, "Did not successfully increase restakedBalanceGwei");
        // Keep track of ValidatorStatus state changes
        _previousStatus = IEigenPod.VALIDATOR_STATUS.ACTIVE;
        validatorData.push(ValidatorData(pubKeyHash, restakedBalanceGwei));
    }

    /**
     * @notice Initiates the withdrawal process.
     * Withdrawal can be either partial (get the rewards) or Full(stop validating and withdraw everything)
     */
    function pokePod(WithdrawalData memory data) external {
        eigenPod.verifyAndProcessWithdrawals(
            data.withdrawalProofs,
            data.validatorFieldsProofs,
            data.validatorFields,
            data.withdrawalFields,
            data.beaconChainETHStrategyIndex,
            data.oracleTimestamp
        );
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function completeWithdrawal() external { }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function getPodProxyManager() public view returns (address payable) {
        return payable(address(_pool));
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function getPodProxyOwner() public view returns (address payable) {
        return payable(_podProxyOwner);
    }

    function _setPodRewardsRecipient(address payable podRewardsRecipient) internal {
        address oldRecipient = _podRewardsRecipient;
        _podRewardsRecipient = podRewardsRecipient;
        emit PodRewardsRecipientChanged(oldRecipient, podRewardsRecipient);
    }

    function _distributeRewards(uint256 amount, uint256 comission) internal {
        uint256 toPod = FixedPointMathLib.fullMulDiv(amount, comission, _ONE_HUNDRED_WAD);
        SafeTransferLib.safeTransferETH(getPodProxyManager(), amount - toPod);
        SafeTransferLib.safeTransferETH(_podRewardsRecipient, toPod);
    }

    function _handleFullWithdrawal(uint256 bond) internal {
        // Forward the msg.value, as this function is called from the `receive()`
        _pool.withdrawFromProtocol{ value: msg.value }(bond, _podRewardsRecipient);
    }
}
