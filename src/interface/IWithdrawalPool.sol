// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Permit } from "puffer/struct/Permit.sol";

/**
 * @title IWithdrawalPool
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IWithdrawalPool {
    /**
     * @notice Thrown if the fee rate is not valid
     * @dev Signature "0x56d69198"
     */
    error InvalidFeeRate();

    /**
     * @notice Emitted when the withdrawal fee is changed
     */
    event WithdrawalFeeChanged(uint256 oldRate, uint256 newRate);

    /**
     * @notice Sets the withdrawal fee to the specified amount
     * @param withdrawalFee The new withdrawal fee to be set
     */
    function setWithdrawalFee(uint256 withdrawalFee) external;

    /**
     * @notice Burns `pufETHAmount` and sends the ETH to `to`
     * @dev You need to approve `pufETHAmount` to this contract by calling pool.approve
     * @return ETH Amount redeemed
     */
    function withdrawETH(address to, uint256 pufETHAmount) external returns (uint256);

    /**
     * @notice Burns pufETH and sends ETH to `to`
     * Permit allows a gasless approval. Owner signs a message giving transfer approval to this contract.
     * @param permit is the struct required by IERC20Permit-permit
     */
    function withdrawETH(address to, Permit calldata permit) external returns (uint256);
}
