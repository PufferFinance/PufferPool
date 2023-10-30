// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

interface IWithdrawalPool {
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
     * @return ETH Amount redeemed
     */
    function withdrawETH(address to, uint256 pufETHAmount) external returns (uint256);

    /**
     * @notice Burns pufETH and sends ETH to `to`
     * Permit allows a gasless approval. Owner signs a message giving transfer approval to this contract.
     * @param permit is the struct required by IERC20Permit-permit
     */
    function withdrawETH(address to, Permit calldata permit) external;
}
