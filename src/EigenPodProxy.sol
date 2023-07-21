// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Initializable } from "openzeppelin/proxy/utils/Initializable.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { BeaconChainProofs } from "eigenlayer/libraries/BeaconChainProofs.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { Math } from "openzeppelin/utils/math/Math.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";

/**
 * @title EingenPodProxy
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 * @notice TODO: interacts with EigenLayer
 */
contract EigenPodProxy is IEigenPodProxy, Initializable {
    // TODO: getters, OZ ownable and/or access control
    address payable internal _owner;

    IPufferPool internal _manager;

    // PodAccount
    IEigenPod public ownedEigenPod;

    // Keeps track of any ETH owed to podOwner, but has not been paid due to slow withdrawal
    uint256 public owedToPodOwner;
    // If ETH hits this contract, and not from the ownedEigenPod contract, consider it execution rewards
    uint256 public executionRewards;

    /**
     * @dev Upgradeable contract from EigenLayer
     */
    IEigenPodManager internal immutable _eigenPodManager;

    constructor(IEigenPodManager eigenPodManager) {
        _eigenPodManager = eigenPodManager;
        _disableInitializers();
    }

    /// @notice Fallback function used to differentiate execution rewards from consensus rewards
    fallback() external payable {
        if (msg.sender != address(ownedEigenPod)) {
            executionRewards += msg.value;
        }
    }

    /// @notice Helper function to get the withdrawal credentials corresponding to the owned eigenPod
    function _getPodWithdrawalCredentials() internal view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(ownedEigenPod));
    }

    receive() external payable { }

    function getManager() external view returns (address) {
        return address(_manager);
    }

    function initialize(address payable owner, IPufferPool manager) external payable initializer {
        _owner = owner;
        _manager = manager;
        // TODO: do we want to deploy pod in initializer so the Validator pays for it?
        // Or we create it when we call stake so the Guraidnas pay for it?
        // eigenPodManager.deployPod()
    }

    modifier onlyOwner() {
        if (msg.sender != _owner) {
            revert Unauthorized();
        }
        _;
    }

    modifier onlyManager() {
        if (msg.sender != address(_manager)) {
            revert Unauthorized();
        }
        _;
    }

    function getEigenPodManager() external view returns (IEigenPodManager) {
        return _eigenPodManager;
    }

    // /**
    //  * @inheritdoc IEigenPodProxy
    //  */
    // function ownedEigenPod() external view returns (address) {
    //     // TODO:
    // }
    /**
     * @inheritdoc IEigenPodProxy
     */

    /**
     * @inheritdoc IEigenPodProxy
     */
    function enableSlashing(address contractAddress) external {
        // TODO:
    }
    /**
     * @inheritdoc IEigenPodProxy
     */
    function registerToAVS(bytes calldata registrationData) external {
        // TODO:
    }
    /**
     * @inheritdoc IEigenPodProxy
     */
    function registerToPufferAVS(bytes calldata registrationData) external {
        // TODO:
    }

    function skimAfterFullWithdraw() external {
        // TODO:
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function initiateWithdrawal(uint256[] calldata shares) external {
        // TODO:
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function enableRestaking(
        uint64 oracleBlockNumber,
        uint40 validatorIndex,
        BeaconChainProofs.ValidatorFieldsAndBalanceProofs memory proofs,
        bytes32[] calldata validatorFields
    ) external {
        // TODO:
    }

    function podProxyManager() external view returns (address) {
        return address(_manager);
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function podProxyOwner() external view returns (address) {
        return _owner;
    }

    /// @notice Creates an EigenPod without depositiing ETH
    function createEmptyPod() external {
        // TODO: we shouldn't do tx.origin auth
        require(tx.origin == _owner, "Only PodProxyOwner allowed");
        require(address(ownedEigenPod) == address(0), "Must not have instantiated EigenPod");

        _eigenPodManager.createPod();

        // This contract is the owner of the created eigenPod
        ownedEigenPod = _eigenPodManager.ownerToPod(address(this));
    }

    /// @notice Initiated by the PufferPool. Calls stake() on the EigenPodManager to deposit Beacon Chain ETH and create another ETH validator
    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable
        onlyManager
    {
        _eigenPodManager.stake{ value: 32 ether }(pubKey, signature, depositDataRoot);
    }

    /// @notice Withdraws full EigenPod balance if they've never restaked
    function earlyWithdraw() external payable onlyOwner {
        ownedEigenPod.withdrawBeforeRestaking();
    }

    /// @notice Deregisters this EigenPodProxy from an AVS
    function deregisterFromAVS() external { }

    /// @notice Called by PufferPool and PodAccount to distribute ETH funds among PufferPool, PodAccount and Puffer Treasury
    function skim() external {
        // TODO: Get the index of the validator corresponding to this eigenpod, so we can fetch the appropriate validator status
        IEigenPod.VALIDATOR_STATUS status = ownedEigenPod.validatorStatus(0);
        uint256 contractBalance = address(this).balance;

        require(
            status != IEigenPod.VALIDATOR_STATUS.WITHDRAWN && status != IEigenPod.VALIDATOR_STATUS.OVERCOMMITTED,
            "Can't be withdrawn or overcommitted"
        );
        require(contractBalance > 0 || owedToPodOwner > 0, "No ETH to skim");

        if (status == IEigenPod.VALIDATOR_STATUS.INACTIVE) {
            if (contractBalance >= 32 ether) {
                _sendETH(_owner, 2 ether + ((contractBalance - 30 ether) * _manager.getPodAVSComission()) / 10 ** 9);
                _sendETH(payable(address(_manager)), address(this).balance);
            } else {
                _sendETH(_owner, Math.max(contractBalance - 30 ether, 0));
                _sendETH(payable(address(_manager)), address(this).balance);
            }
            // Reset execution rewards because we just withdrew all ETH
            executionRewards = 0;
        }
        // TODO: How to determine the rewards which come from an AVS from consensus rewards?
        else if (status == IEigenPod.VALIDATOR_STATUS.ACTIVE) {
            _sendETH(
                _owner,
                (
                    (contractBalance - executionRewards) * _manager.getConsensusRewardsSplit()
                        + executionRewards * _manager.getExecutionRewardsSplit()
                ) / 10 ** 9
            );
            _sendETH(payable(address(_manager)), address(this).balance);
            // Reset execution rewards after skimming
            executionRewards = 0;
        }
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
