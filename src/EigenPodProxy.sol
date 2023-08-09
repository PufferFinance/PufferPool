// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Initializable } from "openzeppelin/proxy/utils/Initializable.sol";
// TODO: Temporarily use a wrapper for EigenPod before eigenpodupdates branch is merged into eigenlayer contracts
import { IEigenPodWrapper } from "puffer/interface/IEigenPodWrapper.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { BeaconChainProofs } from "eigenlayer/libraries/BeaconChainProofs.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
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
     * @dev Exchange rate 1 is represented as 10 ** 18
     */
    uint256 internal constant _ONE = 10 ** 18;

    /**
     * @dev Constant representing 100%
     */
    uint256 internal constant _ONE_HUNDRED = 100 * _ONE;

    /**
     * @dev {Safe} PodAccount is the pod proxy owner
     */
    address payable internal _podProxyOwner;

    /**
     * @dev PufferPool is the pod proxy manager
     */
    IPufferPool internal _podProxyManager;

    /**
     * @dev The designated address to send pod rewards. Can be changed by podProxyOwner(PodAccount)
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

    /**
     * @dev Public Key corresponding to validator. Used to fetch validator status
     */
    bytes internal _pubKey;

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

    /**
     * @dev Pod owner and PufferPool are allowed
     */
    modifier onlyOwnerAndManager() {
        if (msg.sender != _podProxyOwner && msg.sender != address(_podProxyManager)) {
            revert Unauthorized();
        }
        _;
    }

    constructor(IEigenPodManager eigenPodManager, ISlasher slasher) {
        _slasher = slasher;
        _eigenPodManager = eigenPodManager;
        _disableInitializers();
    }

    function initialize(IPufferPool manager, uint256 bond) external initializer {
        _bond = bond;
        _podProxyManager = manager;
        _previousStatus = IEigenPodWrapper.VALIDATOR_STATUS.INACTIVE;
        _eigenPodManager.createPod();
        ownedEigenPod = IEigenPodWrapper(address(_eigenPodManager.ownerToPod(address(this))));
    }

    /// @notice Fallback function used to differentiate execution rewards from consensus rewards
    receive() external payable {
        // If bond is already withdrawn, send any incoming money directly to pool
        if (bondWithdrawn) {
            _sendETH(payable(address(_podProxyManager)), msg.value);
            return;
        } else if (AVSPaymentAddresses[msg.sender]) {
            _distributeAvsRewards(msg.value);
        } else if (msg.sender != address(ownedEigenPod)) {
            _distributeExecutionRewards(msg.value);
        } else {
            IEigenPodWrapper.VALIDATOR_STATUS currentStatus = ownedEigenPod.validatorStatus(keccak256(_pubKey));
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

    /**
     * @inheritdoc IEigenPodProxy
     */
    function getProxyManager() external view returns (IPufferPool) {
        return _podProxyManager;
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
        require(!bondWithdrawn, "The bond has been withdrawn, cannot stake");
        staked = true;
        _eigenPodManager.stake{ value: 32 ether }(pubKey, signature, depositDataRoot);
        _pubKey = pubKey;
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function stopRegistraion() external onlyPodProxyOwner {
        require(!staked, "pufETH bond is locked, because pod is already staking");
        bondWithdrawn = true;
        _podProxyManager.transfer(_podRewardsRecipient, _podProxyManager.balanceOf(address(this)));
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function enableSlashing(address contractAddress) external {
        if (contractAddress != _podProxyManager.getPufferAvsAddress()) {
            require(msg.sender == _podProxyOwner, "Only PodProxyOwner can register to non Puffer AVS");
        }
        if (!_podProxyManager.isAVSEnabled(contractAddress)) {
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
     * @inheritdoc IEigenPodProxy
     */
    function initiateWithdrawal() external {
        // Withdraw all available ETH
        uint256[] memory shares;
        shares[0] = uint256(ownedEigenPod.withdrawableRestakedExecutionLayerGwei());

        // Hardcoded values
        uint256[] memory strategyIndexes;
        strategyIndexes[0] = _podProxyManager.getBeaconChainETHStrategyIndex();
        IStrategy[] memory strategies;
        strategies[0] = _podProxyManager.getBeaconChainETHStrategy();

        _podProxyManager.getStrategyManager().queueWithdrawal(strategyIndexes, strategies, shares, address(this), true);
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
        uint40 validatorIndex,
        bytes memory proofs,
        bytes32[] calldata validatorFields
    ) external {
        ownedEigenPod.verifyWithdrawalCredentialsAndBalance(oracleBlockNumber, validatorIndex, proofs, validatorFields);
        // Keep track of ValidatorStatus state changes
        _previousStatus = IEigenPodWrapper.VALIDATOR_STATUS.ACTIVE;
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function verifyAndWithdraw(
        BeaconChainProofs.WithdrawalProofs calldata withdrawalProofs,
        bytes calldata validatorFieldsProof,
        bytes32[] calldata validatorFields,
        bytes32[] calldata withdrawalFields,
        uint256 beaconChainETHStrategyIndex,
        uint64 oracleBlockNumber
    ) external {
        ownedEigenPod.verifyAndProcessWithdrawal(
            withdrawalProofs,
            validatorFieldsProof,
            validatorFields,
            withdrawalFields,
            beaconChainETHStrategyIndex,
            oracleBlockNumber
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
        return payable(address(_podProxyManager));
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

    function _distributeFunds(uint256 total, uint256 toPod) internal {
        _sendETH(_podRewardsRecipient, toPod);
        _sendETH(getPodProxyManager(), total - toPod);
    }

    function _distributeAvsRewards(uint256 amount) internal {
        uint256 toPod = (amount * _podProxyManager.getAvsCommission()) / _ONE_HUNDRED;
        _distributeFunds(amount, toPod);
    }

    function _distributeExecutionRewards(uint256 amount) internal {
        uint256 toPod = (amount * _podProxyManager.getExecutionCommission()) / _ONE_HUNDRED;
        _distributeFunds(amount, toPod);
    }

    function _distributeConsensusRewards(uint256 amount) internal {
        uint256 toPod = (amount * _podProxyManager.getConsensusCommission()) / _ONE_HUNDRED;
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
        uint256 podsCut = (skimmable * _podProxyManager.getConsensusCommission()) / _ONE_HUNDRED;
        _sendETH(_podRewardsRecipient, podsCut);

        // ETH owed to pool
        uint256 poolCut = skimmable - podsCut;
        _sendETH(getPodProxyManager(), poolCut);

        // Update previous status to withdrawn
        _previousStatus = IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN;
    }

    function _sendETH(address payable to, uint256 amount) internal {
        if (amount == 0) {
            return;
        }
        bool success;

        /// @solidity memory-safe-assembly
        assembly {
            // Transfer the ETH and store if it succeeded or not.
            success := call(gas(), to, amount, 0, 0, 0, 0)
        }

        require(success);
    }
}
