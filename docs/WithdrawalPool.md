# WithdrawalPool

WithdrawalPool is a smart contract that allows Puffers to exchange their `pufETH` for ETH by calling one of our two versions:
- `withdrawETH(address to, uint256 pufETHAmount)` 
    - To ensure this function doesn't revert, the caller must first approve `pufETHAmount` to the WithdrawalPool smart contract by calling `pufferPool.approve(withdrawalPoolAddress, pufETHAmount)`.
- `withdrawETH(address to, Permit calldata permit)`
    - In this flow, the user is prompted to sign a gasless approval message, and after that is done, the `withdrawETH` is executed.

Both versions of `withdrawETH` fetch the exchange rate from PufferPool and use it to swap `pufETH` for `ETH` if there is enough liquidity in this smart contract.
