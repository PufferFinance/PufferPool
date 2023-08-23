// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";

/**
 * @title WithdrawalPool
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
contract WithdrawalPool {
    error WithdrawalNotProcessed();

    PufferPool public immutable pool;

    constructor(PufferPool pufferPool) {
        pool = pufferPool;
    }

    mapping(uint256 => Withdrawal) internal _withdrawalQueue;
    uint256 internal _lastId;

    uint256 internal _lockedTime = 3 days;

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

    receive() external payable { }

    function withdrawETH(address recipient, Permit calldata permit) external {
        // If permit owner is address zero, skip the permit call
        // That means that the user is doing this in two transactions
        // 1. pufETH.approve(address(this), amount)
        // 2. withdrawalPool.withdrawETH(recipient, amount)
        if (permit.r != bytes32("")) {
            // Approve pufETH from owner to this contract
            pool.permit({
                owner: permit.owner,
                spender: address(this),
                value: permit.amount,
                deadline: permit.deadline,
                v: permit.v,
                s: permit.s,
                r: permit.r
            });
        }

        // Transfer pufETH from the owner to this contract
        pool.transferFrom(permit.owner, address(this), permit.amount);

        // Calculate ETH amount
        uint256 ethAmount = pool.calculatePufETHtoETHAmount(permit.amount);

        // Burn PufETH
        pool.burn(permit.amount);

        // Send ETH to the recipient
        _safeTransferETH(recipient, ethAmount);
    }

    /**
     * @dev Helper function for transfering ETH
     * https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol
     */
    function _safeTransferETH(address to, uint256 amount) internal {
        bool success;

        /// @solidity memory-safe-assembly
        assembly {
            // Transfer the ETH and store if it succeeded or not.
            success := call(gas(), to, amount, 0, 0, 0, 0)
        }

        require(success);
    }
}
