// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";
import { BeaconChainProofs } from "eigenlayer/libraries/BeaconChainProofs.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IERC20 } from "openzeppelin/token/ERC20/IERC20.sol";

/**
 * @title IPufferModule
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferModule {
    /**
     * @notice Emits when rewards are claimed
     * @param node is the node address
     * @param amount is the amount claimed in wei
     */
    event RewardsClaimed(address indexed node, uint256 amount);

    /**
     * @notice Returns the Withdrawal credentials for that module
     */
    function getWithdrawalCredentials() external view returns (bytes memory);

    /**
     * @notice Returns the module name
     */
    function NAME() external view returns (bytes32);

    /**
     * @notice Starts the validator
     */
    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot) external payable;

    /**
     * @notice Calls the delegateTo function on the EigenLayer delegation manager
     * @param operator is the address of the restaking operator
     * @param approverSignatureAndExpiry the signature of the delegation approver
     * @param approverSalt salt for the signature
     * @dev Restricted to the DAO
     */
    function callDelegateTo(
        address operator,
        ISignatureUtils.SignatureWithExpiry calldata approverSignatureAndExpiry,
        bytes32 approverSalt
    ) external;

    /**
     * @notice Calls the undelegate function on the EigenLayer delegation manager
     * @dev Restricted to the DAO
     */
    function callUndelegate() external returns (bytes32[] memory withdrawalRoot);

    /**
     * @notice Returns the EigenPod address owned by the module
     */
    function getEigenPod() external view returns (address);

    /**
     * @notice Queues the withdrawal from EigenLayer for the Beacon Chain strategy
     * @dev Restricted to PufferModuleManager
     */
    function queueWithdrawals(uint256 shareAmount) external;

    /**
     * @notice Verifies and processes the withdrawals
     */
    function verifyAndProcessWithdrawals(
        uint64 oracleTimestamp,
        BeaconChainProofs.StateRootProof calldata stateRootProof,
        BeaconChainProofs.WithdrawalProof[] calldata withdrawalProofs,
        bytes[] calldata validatorFieldsProofs,
        bytes32[][] calldata validatorFields,
        bytes32[][] calldata withdrawalFields
    ) external;

    /**
     * @notice Verifies the withdrawal credentials
     */
    function verifyWithdrawalCredentials(
        uint64 oracleTimestamp,
        BeaconChainProofs.StateRootProof calldata stateRootProof,
        uint40[] calldata validatorIndices,
        bytes[] calldata validatorFieldsProofs,
        bytes32[][] calldata validatorFields
    ) external;

    /**
     * @notice Completes the queued withdrawals
     */
    function completeQueuedWithdrawals(
        IDelegationManager.Withdrawal[] calldata withdrawals,
        IERC20[][] calldata tokens,
        uint256[] calldata middlewareTimesIndexes
    ) external;

    /**
     * @notice Withdraws the non beacon chain ETH balance
     */
    function withdrawNonBeaconChainETHBalanceWei(uint256 amountToWithdraw) external;

    /**
     * @notice Function callable only by PufferProtocol
     * @param to is the destination address
     * @param amount is the ETH amount in wei
     * @param data is the calldata
     */
    function call(address to, uint256 amount, bytes calldata data)
        external
        returns (bool success, bytes memory response);
}
