// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title ValidatorTicketStorage
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
abstract contract ValidatorTicketStorage {
    struct ValidatorTicket {
        /**
         * @dev The amount of ETH needed to mint 1 ValidatorTicket
         * Slot 1
         */
        uint256 mintPrice;
        /**
         * @dev This is how much ETH we immediately send to the PufferVault, holding the rest to later give to Guardians and Treasury
         * Slot 2
         */
        uint256 sendOnReceive;
        /**
         * @dev This defines how much of this contract balance we give to the Treasury, giving the rest to Guardians
         * Slot 3
         */
        uint64 treasuryFee;
        /**
         * @dev Puffer Finance Guardians address
         * Slot 4
         */
        address payable guardians;
        /**
         * @dev Puffer Finance oracle address
         * Slot 5
         */
         address oracle;
    }
    /**
     * @dev Constant representing 100%
     */
    uint256 internal constant _ONE_HUNDRED_WAD = 100 * 1e18; // 1e18 = WAD

    /**
     * @dev Storage slot location for ValidatorTicket
     * @custom:storage-location erc7201:ValidatorTicket.storage
     */
    bytes32 private constant _VALIDATOR_TICKET_STORAGE =
        0x522b25b4b3844af9be07fc1b83a538fd31925481b968b15976cafed863007000;

    function _getValidatorTicketStorage() internal pure returns (ValidatorTicket storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := _VALIDATOR_TICKET_STORAGE
        }
    }
}
