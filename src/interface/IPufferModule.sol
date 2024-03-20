// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";

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
     * @notice Emitted when the Puffer Module is delegated
     * @param operator the operator to delegate to
     */
    event PufferModuleDelegated(address operator);

    /**
     * @notice Emitted when the Puffer Module is undelegated
     */
    event PufferModuleUndelegated();

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
     * @notice Queues the withdrawals for `shareAmount` for Beacon Chain Strategy
     */
    function queueWithdrawals(uint256 shareAmount) external;

    /**
     * @notice Returns the EigenPod address owned by the module
     */
    function getEigenPod() external view returns (address);

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
