// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IPufferOracle } from "puffer/interface/IPufferOracle.sol";

/**
 * @title PufferOracle
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferOracle is IPufferOracle {
    /**
     * @dev Number of blocks
     */
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

    IGuardianModule public immutable GUARDIAN_MODULE;

    constructor(IGuardianModule guardianModule) {
        GUARDIAN_MODULE = guardianModule;
    }

    /**
     * @notice Simulate proofOfReservers from the guardians
     */
    function proofOfReserve(
        uint256 newEthAmountValue,
        uint256 newLockedEthValue,
        uint256 pufETHTotalSupplyValue, // @todo what to do with this?
        uint256 blockNumber,
        uint256 numberOfActiveValidators,
        bytes[] calldata guardianSignatures
    ) external {
        // Check the signatures (reverts if invalid)
        GUARDIAN_MODULE.validateProofOfReserve({
            ethAmount: ethAmount,
            lockedETH: lockedETH,
            pufETHTotalSupply: pufETHTotalSupply,
            blockNumber: blockNumber,
            numberOfActiveValidators: numberOfActiveValidators,
            guardianSignatures: guardianSignatures
        });

        if ((block.number - lastUpdate) < _UPDATE_INTERVAL) {
            revert OutsideUpdateWindow();
        }

        ethAmount = newEthAmountValue;
        lockedETH = newLockedEthValue;
        pufETHTotalSupply = pufETHTotalSupply;
        lastUpdate = blockNumber;

        emit BackingUpdated(newEthAmountValue, newLockedEthValue, pufETHTotalSupplyValue, blockNumber);
    }
}
