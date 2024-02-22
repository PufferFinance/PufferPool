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
         * @dev Protocol fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
         * Because we are using uint64, that means that the max protocol fee rate is 18.44%
         * Slot 1
         */
        uint128 protocolFeeRate;
        /**
         * @dev Guardians fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
         * Because we are using uint64, that means that the max protocol fee rate is 18.44%
         * Slot 1
         */
        uint128 guardiansFeeRate;
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
