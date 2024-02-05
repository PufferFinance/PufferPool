// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IPufferOracle } from "puffer/interface/IPufferOracle.sol";
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

    IGuardianModule public immutable GUARDIAN_MODULE;

    constructor(IGuardianModule guardianModule, address accessManager) AccessManaged(accessManager) {
        GUARDIAN_MODULE = guardianModule;
        _setMintPrice(uint56(0.01 ether));
    }

    function proofOfReserve(
        uint256 newLockedEthValue,
        uint256 blockNumber,
        uint256 pufferMarketShare,
        bytes[] calldata guardianSignatures
    ) external {
        //@todo update module Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validateProofOfReserve({
            ethAmount: 0,
            lockedETH: lockedETH,
            pufETHTotalSupply: 0,
            blockNumber: blockNumber,
            numberOfActiveValidators: 0,
            guardianSignatures: guardianSignatures
        });

        if ((block.number - lastUpdate) < _UPDATE_INTERVAL) {
            revert OutsideUpdateWindow();
        }

        lockedETH = newLockedEthValue;
        lastUpdate = blockNumber;

        emit BackingUpdated(blockNumber, newLockedEthValue);
    }

    /**
     * @notice Updates the price to mint VT
     * @param newPrice The new price to set for minting VT
     */
    function setMintPrice(uint56 newPrice) external restricted {
        _setMintPrice(newPrice);
    }

    function _setMintPrice(uint56 newPrice) internal {
        uint256 oldPrice = _validatorTicketPrice;
        _validatorTicketPrice = newPrice;
        emit ValidatorTicketMintPriceUpdated(oldPrice, newPrice);
    }

    /**
     * @inheritdoc IPufferOracle
     */
    function getValidatorTicketPrice() external view returns (uint256) {
        return _validatorTicketPrice;
    }
}
