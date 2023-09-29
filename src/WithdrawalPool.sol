// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";

/**
 * @title WithdrawalPool
 * @notice Users can burn their pufETH and get ETH from this pool
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */

contract WithdrawalPool {
    using SafeTransferLib for address;

    PufferPool public immutable POOL;

    uint256 internal immutable _ONE_HUNDRED_WAD = 100 * FixedPointMathLib.WAD;

    // @todo Figure out if we want a setter or a constant
    uint256 internal constant _withdrawalFee = FixedPointMathLib.WAD; // 1%
    // uint256 internal constant _withdrawalFee = 0;

    constructor(PufferPool pufferPool) payable {
        POOL = pufferPool;
    }

    struct Withdrawal {
        uint256 pufETH;
        uint256 ETH;
        uint256 lockedUntil;
        address recipient;
    }

    struct Permit {
        address owner;
        uint256 deadline;
        uint256 amount;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /**
     * @notice Burns `pufETHAmount` and sends the ETH to `to`
     * @dev You need to approve `pufETHAmount` to this contract by calling pool.approve
     */
    function withdrawETH(address to, uint256 pufETHAmount) external {
        _withdrawETH(msg.sender, to, pufETHAmount);
    }

    /**
     *
     * @notice Burns pufETH and sends ETH to `to`
     * Permit allows a gasless approval. Owner signs a message giving transfer approval to this contract.
     * @param permit is the struct required by IERC20Permit-permit
     */
    function withdrawETH(address to, Permit calldata permit) external {
        // @audit-issue if the attacker gets PERMIT calldata, he can steal money from the permit.owner
        // @audit-issue it is important that signature is not stored anywhere
        // @audit-issue frontend hack could cause harm here

        // Approve pufETH from owner to this contract
        POOL.permit({
            owner: permit.owner,
            spender: address(this),
            value: permit.amount,
            deadline: permit.deadline,
            v: permit.v,
            s: permit.s,
            r: permit.r
        });

        _withdrawETH(permit.owner, to, permit.amount);
    }

    function _withdrawETH(address from, address to, uint256 pufETHAmount) internal {
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

        to.safeTransferETH(ethAmount - fee);
    }
}
