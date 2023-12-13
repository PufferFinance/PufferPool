// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { Permit } from "puffer/struct/Permit.sol";

/**
 * @title WithdrawalPool
 * @notice Users can burn their pufETH and get ETH from this pool
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract WithdrawalPool is IWithdrawalPool, AccessManaged {
    using SafeTransferLib for address;

    /**
     * @notice PufferPool
     */
    PufferPool public immutable POOL;

    /**
     * @dev A constant representing `100%`
     */
    uint256 internal constant _ONE_HUNDRED_WAD = 100 * FixedPointMathLib.WAD;

    /**
     * @dev Withdrawal fee amount
     */
    uint256 internal _withdrawalFee = FixedPointMathLib.WAD; // 1%

    constructor(PufferPool pufferPool, address initialAuthority) payable AccessManaged(initialAuthority) {
        POOL = pufferPool;
    }

    receive() external payable { }

    /**
     * @inheritdoc IWithdrawalPool
     */
    function withdrawETH(address to, uint256 pufETHAmount) external restricted returns (uint256) {
        return _withdrawETH(msg.sender, to, pufETHAmount);
    }

    /**
     * @inheritdoc IWithdrawalPool
     */
    function setWithdrawalFee(uint256 withdrawalFee) external restricted {
        // Revert if bigger than 3%
        if (withdrawalFee > (3 * FixedPointMathLib.WAD)) {
            revert InvalidFeeRate();
        }
        uint256 oldRate = _withdrawalFee;
        _withdrawalFee = withdrawalFee;
        emit WithdrawalFeeChanged(oldRate, withdrawalFee);
    }

    /**
     * @inheritdoc IWithdrawalPool
     */
    function withdrawETH(address to, Permit calldata permit) external restricted returns (uint256) {
        // Approve pufETH from owner to this contract
        try POOL.permit({
            owner: msg.sender,
            spender: address(this),
            value: permit.amount,
            deadline: permit.deadline,
            v: permit.v,
            s: permit.s,
            r: permit.r
        }) { } catch { }

        // Only permit signer (msg.sender) can use the permit
        return _withdrawETH(msg.sender, to, permit.amount);
    }

    function _withdrawETH(address from, address to, uint256 pufETHAmount) internal returns (uint256) {
        // Transfer pufETH from the owner to this contract
        // pufETH contract reverts, no need to check for return value
        // slither-disable-start arbitrary-send-erc20-permit
        // slither-disable-next-line unchecked-transfer
        POOL.transferFrom(from, address(this), pufETHAmount);
        // slither-disable-end arbitrary-send-erc20-permit

        // Calculate ETH amount
        uint256 ethAmount = POOL.calculatePufETHtoETHAmount(pufETHAmount);

        // There is a withdrawal fee that is staying in the WithdrawalPool
        // It is not going to treasury, it is distributed to all pufETH holders
        uint256 fee = FixedPointMathLib.fullMulDiv(ethAmount, _withdrawalFee, _ONE_HUNDRED_WAD);

        // Burn PufETH
        POOL.burn(pufETHAmount);

        uint256 amount = ethAmount - fee;

        to.safeTransferETH(amount);

        return amount;
    }
}
