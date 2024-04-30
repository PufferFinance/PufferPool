// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @notice Thrown when the operation is not authorized
 * @dev Signature "0x82b42900"
 */
error Unauthorized();

/**
 * @notice Thrown if the address supplied is not valid
 * @dev Signature "0xe6c4247b"
 */
error InvalidAddress();

/**
 * @notice Thrown if the custom call failed
 * @dev Signature "0x5515e1c7"
 */
error CustomCallFailed(address target, bytes returnData);
