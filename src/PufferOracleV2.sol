// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IPufferOracleV2 } from "pufETH/interface/IPufferOracleV2.sol";
import { IPufferOracle } from "pufETH/interface/IPufferOracle.sol";
import { AccessManaged } from "@openzeppelin/contracts/access/manager/AccessManaged.sol";

/**
 * @title PufferOracle
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferOracleV2 is IPufferOracleV2, AccessManaged {
    /**
     * @dev Number of blocks
     */
    // @todo
    // slither-disable-next-line unused-state
    uint256 internal constant _UPDATE_INTERVAL = 1;

    /**
     * @dev Burst threshold
     */
    uint256 internal constant _BURST_THRESHOLD = 22;

    /**
     * @notice Guardian Module
     */
    IGuardianModule public immutable GUARDIAN_MODULE; //@todo ..?

    /**
     * @dev Locked ETH amount in Beacon Chain
     * Slot 0
     */
    uint152 internal _lockedETH;

    /**
     * @dev Block number for when the values were updated
     * Slot 0
     */
    uint56 internal _lastUpdate;

    /**
     * @dev Number of active Puffer validators
     * Slot 0
     */
    uint24 internal _numberOfActivePufferValidators;

    /**
     * @dev Total number of Validators
     * Slot 0
     */
    uint24 internal _totalNumberOfValidators;

    /**
     * @dev Price in ETH to mint one Validator Ticket
     * Slot 1
     */
    uint256 internal _validatorTicketPrice;

    constructor(IGuardianModule guardianModule, address accessManager) AccessManaged(accessManager) {
        GUARDIAN_MODULE = guardianModule;
        _totalNumberOfValidators = 927122; // Oracle will be updated with the correct value
        _setMintPrice(uint56(0.01 ether));
    }

    /**
     * @notice Posts the proof of reserve to the Oracle
     * @param newLockedETH The new locked ETH amount in Beacon chain
     * @param blockNumber The block number of the update
     * @param numberOfActivePufferValidators The number of active Puffer validators
     * @param totalNumberOfValidators The total number of active validators
     * @param guardianSignatures The signatures of the Guardians
     */
    function proofOfReserve(
        uint152 newLockedETH,
        uint56 blockNumber,
        uint24 numberOfActivePufferValidators,
        uint24 totalNumberOfValidators,
        bytes[] calldata guardianSignatures
    ) external {
        GUARDIAN_MODULE.validateProofOfReserve({
            lockedETH: newLockedETH,
            blockNumber: blockNumber,
            numberOfActivePufferValidators: numberOfActivePufferValidators,
            totalNumberOfValidators: totalNumberOfValidators,
            guardianSignatures: guardianSignatures
        });

        if ((block.number - _lastUpdate) < _UPDATE_INTERVAL) {
            revert OutsideUpdateWindow();
        }

        _lockedETH = newLockedETH;
        _lastUpdate = blockNumber;
        _numberOfActivePufferValidators = numberOfActivePufferValidators;
        _totalNumberOfValidators = totalNumberOfValidators;

        emit ReservesUpdated({
            blockNumber: blockNumber,
            lockedETH: newLockedETH,
            numberOfActivePufferValidators: numberOfActivePufferValidators,
            totalNumberOfValidators: totalNumberOfValidators
        });
    }

    /**
     * @notice Increases the `_lockedETH` amount on the Oracle by 32 ETH
     * It is called when the Beacon chain receives a new deposit from PufferProtocol
     * The PufferVault balance is decreased by the same amount
     * @dev Restricted to PufferProtocol contract
     */
    function provisionNode() external restricted {
        _lockedETH += 32 ether;
        unchecked {
            ++_numberOfActivePufferValidators;
        }
    }

    /**
     * @notice Updates the price to mint VT
     * @param newPrice The new price to set for minting VT
     * @dev Restricted to the DAO
     */
    function setMintPrice(uint56 newPrice) external restricted {
        _setMintPrice(newPrice);
    }

    /**
     * @inheritdoc IPufferOracle
     */
    function getLockedEthAmount() external view returns (uint256) {
        return _lockedETH;
    }

    /**
     * @inheritdoc IPufferOracleV2
     */
    function getTotalNumberOfValidators() external view returns (uint256) {
        return _totalNumberOfValidators;
    }

    /**
     * @inheritdoc IPufferOracleV2
     */
    function getLastUpdate() external view returns (uint256) {
        return _lastUpdate;
    }

    /**
     * @inheritdoc IPufferOracle
     */
    function isOverBurstThreshold() external view returns (bool) {
        return ((_numberOfActivePufferValidators * 100 / _totalNumberOfValidators) > _BURST_THRESHOLD);
    }

    /**
     * @inheritdoc IPufferOracle
     */
    function getValidatorTicketPrice() external view returns (uint256) {
        return _validatorTicketPrice;
    }

    function _setMintPrice(uint56 newPrice) internal {
        emit ValidatorTicketMintPriceUpdated(_validatorTicketPrice, newPrice);
        _validatorTicketPrice = newPrice;
    }
}
