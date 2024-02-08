// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IPufferOracle } from "pufETH/interface/IPufferOracle.sol";
import { AccessManaged } from "@openzeppelin/contracts/access/manager/AccessManaged.sol";

/**
 * @title PufferOracle
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferOracle is IPufferOracle, AccessManaged {
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
     * @dev Locked ETH amount in Beacon Chain
     * Slot 1
     */
    uint256 public lockedETH;

    /**
     * @dev Block number for when the values were updated
     * Slot 2
     */
    uint256 public lastUpdate;

    /**
     * @dev Price in ETH to mint one Validator Ticket
     */
    uint256 internal _validatorTicketPrice;

    /**
     * @dev Number of active Puffer validators
     */
    uint256 internal _numberOfActivePufferValidators;

    /**
     * @dev Total number of Validators
     */
    uint256 internal _totalNumberOfValidators;

    IGuardianModule public immutable GUARDIAN_MODULE;

    constructor(IGuardianModule guardianModule, address accessManager) AccessManaged(accessManager) {
        GUARDIAN_MODULE = guardianModule;
        _totalNumberOfValidators = 927122; // Oracle will be updated with the correct value
        _setMintPrice(uint56(0.01 ether));
    }

    function proofOfReserve(
        uint256 newLockedETH,
        uint256 blockNumber,
        uint256 numberOfActivePufferValidators,
        uint256 totalNumberOfValidators,
        bytes[] calldata guardianSignatures
    ) external {
        GUARDIAN_MODULE.validateProofOfReserve({
            lockedETH: newLockedETH,
            blockNumber: blockNumber,
            numberOfActivePufferValidators: numberOfActivePufferValidators,
            totalNumberOfValidators: totalNumberOfValidators,
            guardianSignatures: guardianSignatures
        });

        if ((block.number - lastUpdate) < _UPDATE_INTERVAL) {
            revert OutsideUpdateWindow();
        }

        lockedETH = newLockedETH;
        lastUpdate = blockNumber;
        _numberOfActivePufferValidators = numberOfActivePufferValidators;
        _totalNumberOfValidators = totalNumberOfValidators;

        //@todo change the event
        emit BackingUpdated(blockNumber, newLockedETH);
    }

    /**
     * @notice Increases the lockedETH amount by 32 ETH
     * @dev Restricted to PufferProtocol contract
     */
    function provisionNode() external restricted {
        lockedETH += 32 ether;
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

    function _setMintPrice(uint56 newPrice) internal {
        emit ValidatorTicketMintPriceUpdated(_validatorTicketPrice, newPrice);
        _validatorTicketPrice = newPrice;
    }

    /**
     * @inheritdoc IPufferOracle
     */
    function getLockedEthAmount() external view returns (uint256) {
        return lockedETH;
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
}
