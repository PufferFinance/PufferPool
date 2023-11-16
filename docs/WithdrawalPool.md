# WithdrawalPool

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- |  -------- |
| [`IWithdrawalPool.sol`](../src/interface/IWithdrawalPool.sol) | Singleton | NO | YES | / |
| [`WithdrawalPool.sol`](../src/WithdrawalPool.sol) | Singleton | NO | / | / |

WithdrawalPool is a smart contract that allows stakers to exchange their `pufETH` for ETH by calling one of two functions:
- `withdrawETH(address to, uint256 pufETHAmount)` 
    - To ensure this function doesn't revert, the caller must first approve `pufETHAmount` to the WithdrawalPool smart contract by calling `pufferPool.approve(withdrawalPoolAddress, pufETHAmount)`.
- `withdrawETH(address to, Permit calldata permit)`
    - In this flow, the user is prompted to sign a gasless approval message, and after that is done, the `withdrawETH` is executed.

Both versions of `withdrawETH` fetch the exchange rate from PufferPool and use it to swap `pufETH` for `ETH` if there is enough liquidity in this smart contract.

#### High-level Concepts

This document organizes methods according to the following themes (click each to be taken to the relevant section):
* [Withdrawing ETH](#withdrawing-eth)

#### Helpful definitions

* `uint256 internal immutable _ONE_HUNDRED_WAD = 100 * FixedPointMathLib.WAD`: An internal constant representing 100%, used for calculations relating to splitting payments
* `PufferPool public immutable POOL`: The `PufferPool` smart contract
* `pufETH`: A token which is minted upon ETH deposits to the PufferPool. It is an appreciating asset which grows as the protocol earns rewards. NoOp bonds are held in pufETH

---

### Withdrawing ETH

#### `withdrawETH`

```solidity
function withdrawETH(address to, uint256 pufETHAmount) external returns (uint256)
```

Burns pufETH, and sends the corresponding amount of ETH to `address to`, in accordance with the current exchange rate between pufETH and ETH

*Effects*:
* Burns pufETH
* Sends ETH to `address to`
* Return value is the amount of ETH sent

*Requirements*:
* Caller must have called `pool.approve` to approve the desired amount of pufETH to be taken by this contract and burned

#### `withdrawETH`

```solidity
function withdrawETH(address to, Permit calldata permit) external
```

This function also burns pufETH, sending the corresponding amount of ETH to `address to`. However, this function does not require an approve call to be made beforehand

*Effects*:
* Burns pufETH
* Sends ETH to `address to`

*Requirements*:
* Owner signs a message giving transfer approval to this contract
