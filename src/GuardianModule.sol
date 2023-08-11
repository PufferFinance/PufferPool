// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Safe } from "safe-contracts/Safe.sol";
import { Enum } from "safe-contracts/common/Enum.sol";
import { Initializable } from "openzeppelin/proxy/utils/Initializable.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";

/**
 * @title Guardian module
 * @author Puffer finance
 * @dev This contract is called via `delegatecall` opcode
 * @custom:security-contact security@puffer.fi
 */
contract GuardianModule is Initializable, IGuardianModule {
    /**
     * @notice This seed is representing a mappin glike this: mapping(address guardian => address guardianEnclave);
     *         We are storing this mapping data in PodAccount's unstructured storage
     * @dev uint256(keccak256("puffer.guardian.keys"))
     */
    uint256 public constant GUARDIAN_KEYS_SEED =
        21179069603049101978888635358919905010850171584254878123552458168785430937385;

    /**
     * @inheritdoc IGuardianModule
     */
    function rotateGuardianKeys(
        address guardianAccount,
        uint256 blockNumber,
        bytes calldata pubKey,
        bytes calldata raveEvidence
    ) external {
        Safe safe = Safe(payable(guardianAccount));
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
     * @notice This function is supposed to be called via delegatecall from "rotateGuardianKeys"
     * @dev DO NOT CALL THIS FUNCTION
     */
    function rotateKeys(address guardian, uint256 blockNumber, bytes calldata pubKey, bytes calldata raveEvidence)
        external
    {
        address computedAddress = address(uint160(uint256(keccak256(pubKey))));

        assembly {
            mstore(0x0c, GUARDIAN_KEYS_SEED)
            mstore(0x00, guardian)
            let storageSlot := keccak256(0x0c, 0x20)
            sstore(storageSlot, computedAddress)
        }

        emit RotatedGuardianKey(guardian, computedAddress);
    }

    /**
     * @inheritdoc IGuardianModule
     */
    function isGuardiansEnclaveAddress(address payable guardianAccount, address guardian, address enclave)
        external
        view
        returns (bool)
    {
        // Compute the storage slot
        uint256 storageSlot;
        assembly ("memory-safe") {
            mstore(0x0c, GUARDIAN_KEYS_SEED)
            mstore(0x00, guardian)
            storageSlot := keccak256(0x0c, 0x20)
        }

        Safe safe = Safe(payable(guardianAccount));

        // Read storage slot from the {Safe}
        bytes memory result = safe.getStorageAt(storageSlot, 1);

        // Decode it
        bytes32 data = abi.decode(result, (bytes32));

        // Assert if the stored enclaveAddress equals enclave
        return address(uint160(uint256(data))) == enclave;
    }
}
