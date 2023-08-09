// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Guard } from "safe-contracts/base/GuardManager.sol";

/**
 * @title IGuardianModule interface
 * @author Puffer Finance
 */
interface IGuardianModule is Guard {
    /**
     * @dev Signature "0x82b42900"
     */
    error Unauthorized();

    /**
     * @notice Thrown if the {Safe} tries to send ETH address other than RewardsSplitter
     * @dev Signature "0x370866e4"
     */
    error BadETHDestination();

    /**
     * @notice Thrown if the {Safe} tries to use delegatecall
     * @dev Signature 0xd91eb4bc
     */
    error DelegateCallIsNotAllowed();

    /**
     * @notice Thrown if the {Safe} tries to use enable module
     * @dev Signature 0xfe98d492
     */
    error EnableModuleIsNotAllowed();

    /**
     * @notice Thrown if the {Safe} tries to use enable module
     * @dev Signature 0x1c82dd57
     */
    error DisableModuleIsNotAllowed();

    /**
     * @notice Emitted when the guardian changes guardian enclave address
     * @param guardian is the address outside of the enclave
     * @param guardianEnclave is the enclave address
     */
    event RotatedGuardianKey(address guardian, address guardianEnclave);

    /**
     * @notice Rotates guardians key
     * @dev If the msg.sender is one of the owners of the `podAccount`, the transaction will be executed.
     *      It executes a delegatecall to this smart contract and calls `rotateKeys`
     *      It will update the guardian's enclave key to address derived from the `pubKey`
     */
    function rotateGuardianKeys(
        address podAccount,
        uint256 blockNumber,
        bytes calldata pubKey,
        bytes calldata raveEvidence
    ) external;

    /**
     * @notice Returns `true` if the `from` is an enclave address of a `podAccount`'s owner
     */
    function isGuardiansEnclaveAddress(address payable podAccount, address from) external view returns (bool);
}
