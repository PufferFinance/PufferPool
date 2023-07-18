// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Initializable } from "openzeppelin/proxy/utils/Initializable.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { BeaconChainProofs } from "eigenlayer/libraries/BeaconChainProofs.sol";

/**
 * @title EingenPodProxy
 * @author Puffer finance
 * @notice TODO: interacts with EigenLayer
 */
contract EigenPodProxy is IEigenPodProxy, Initializable {
    /**
     * @dev Thrown if the msg.sender is unauthorized.
     */
    error Unauthorized();

    // TODO: getters, OZ ownable?
    address internal _owner;
    address internal _manager;

    /**
     * @dev Upgradeable contract from EigenLayer
     */
    IEigenPodManager internal immutable _eigenPodManager;

    constructor(IEigenPodManager eigenPodManager) {
        _eigenPodManager = eigenPodManager;
        _disableInitializers();
    }

    receive() external payable { }
    fallback() external payable { }

    function getManager() external view returns (address) {
        return _manager;
    }

    function initialize(address owner, address manager) external payable initializer {
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
        if (msg.sender != _manager) {
            revert Unauthorized();
        }
        _;
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

    function skim() external {
        // TODO:
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function ownedEigenPod() external view returns (address) {
        // TODO:
    }
    /**
     * @inheritdoc IEigenPodProxy
     */
    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable
        onlyManager
    {
        // TODO:

        // eigenPodManager.stake() ...
    }
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

    /**
     * @inheritdoc IEigenPodProxy
     */
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
        // TODO:
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function podProxyManager() external view returns (address) {
        return _manager;
    }

    /**
     * @inheritdoc IEigenPodProxy
     */
    function podProxyOwner() external view returns (address) {
        return _owner;
    }
}
