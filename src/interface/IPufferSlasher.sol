// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

interface IPufferSlasher {
    /**
     * @notice Thrown when the user is not authorized
     * @dev Signature "0x82b42900"
     */
    error Unauthorized();

    /**
     * @notice Calls function to freeze operator on EigenLayer's Slasher contract
     */
    function slash(address operator) external;
}
