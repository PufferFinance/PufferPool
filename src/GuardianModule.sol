// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Safe } from "safe-contracts/Safe.sol";
import { ModuleManager } from "safe-contracts/base/ModuleManager.sol";
import { GuardManager } from "safe-contracts/base/GuardManager.sol";
import { Enum } from "safe-contracts/common/Enum.sol";
import { BaseGuard } from "safe-contracts/base/GuardManager.sol";
import { Initializable } from "openzeppelin/proxy/utils/Initializable.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";

/**
 * @title Guardian module
 * @author Puffer finance
 * @dev This contract is called via `delegatecall` opcode
 * @custom:security-contact security@puffer.fi
 */
contract GuardianModule is Initializable, BaseGuard, IGuardianModule {
    /**
     * @dev This is the storage slot of {Safe} guard
     * keccak256("guard_manager.guard.address")
     */
    bytes32 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /**
     * @notice This seed is representing a mappin glike this: mapping(address guardianEnclave => address guardian);
     *         We are storing this mapping data in PodAccount's unstructured storage
     * @dev uint256(keccak256("puffer.guardian.keys"))
     */
    uint256 public constant GUARDIAN_KEYS_SEED =
        21179069603049101978888635358919905010850171584254878123552458168785430937385;

    /**
     * @notice Address of the PufferPool rewards splitter
     */
    address public immutable splitter;

    constructor(address _splitter) {
        splitter = _splitter;
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function rotateGuardianKeys(
        address podAccount,
        uint256 blockNumber,
        bytes calldata pubKey,
        bytes calldata raveEvidence
    ) external {
        Safe safe = Safe(payable(podAccount));
        // Because this is called from the safe via .delegateCall
        // address(this) equals to {Safe}
        // This will revert if the caller is not one of the {Safe} owners
        if (!safe.isOwner(msg.sender)) {
            revert Unauthorized();
        }

        safe.execTransactionFromModule({
            to: address(this),
            value: 0,
            data: abi.encodeCall(GuardianModule.rotateKeys, (msg.sender, blockNumber, pubKey, raveEvidence)),
            operation: Enum.Operation.DelegateCall
        });
    }

    /**
     * @notice This function is not supposed to be called normally, it is supposed to be called via delegatecall from rotateGuardianKeys function.
     * @dev DO NOT CALL THIS FUNCTION
     */
    function rotateKeys(address guardian, uint256 blockNumber, bytes calldata pubKey, bytes calldata raveEvidence)
        external
    {
        address computedAddress = address(uint160(uint256(keccak256(pubKey))));

        assembly {
            mstore(0x0c, GUARDIAN_KEYS_SEED)
            mstore(0x00, computedAddress)
            let storageSlot := keccak256(0x0c, 0x20)
            sstore(storageSlot, guardian)
        }

        emit RotatedGuardianKey(guardian, computedAddress);
    }

    /**
     * @notice This function serves as a PodAccount's guard
     * @dev It will prevent sending ETH directly to address other than `splitter`
     *      It will also prevent any delegatecalls, so that it can't be selfdestructed or bypassed
     */
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external {
        // Prevent sending ETH from this contract unless it is our fee splitter
        if (value != 0) {
            if (to != splitter) {
                revert BadETHDestination();
            }
        }

        // Prevent delegatecall anywhere
        if (operation == Enum.Operation.DelegateCall) {
            revert DelegateCallIsNotAllowed();
        }

        bytes4 selector;
        assembly {
            selector := mload(add(data, 32))
        }

        // Prevent adding new modules
        if (selector == ModuleManager.enableModule.selector) {
            revert EnableModuleIsNotAllowed();
        }

        // Prevent disabling modules
        if (selector == ModuleManager.disableModule.selector) {
            revert DisableModuleIsNotAllowed();
        }
    }

    /**
     * @dev Prevents PodAccount's owners of removing this contract as a guard
     */
    function checkAfterExecution(bytes32, bool) external view {
        // Fetch the value in GUARD_STORAGE_SLOT
        bytes memory result = Safe(payable(msg.sender)).getStorageAt(uint256(GUARD_STORAGE_SLOT), 1);

        // Check if the owners tried to remove this guard
        if (abi.decode(result, (address)) != address(this)) {
            revert Unauthorized();
        }
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function isGuardiansEnclaveAddress(address payable podAccount, address from) external view returns (bool) {
        // Compute the storage slot
        uint256 storageSlot;
        assembly ("memory-safe") {
            mstore(0x0c, GUARDIAN_KEYS_SEED)
            mstore(0x00, from)
            storageSlot := keccak256(0x0c, 0x20)
        }

        Safe safe = Safe(payable(podAccount));

        // Read stoage slot from the {Safe}
        bytes memory result = safe.getStorageAt(storageSlot, 10);

        // Decode it
        address guardian = abi.decode(result, (address));

        // Check if it is comming from the {Safe} owner
        return safe.isOwner(guardian);
    }
}
