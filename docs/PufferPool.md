# PufferPool

PufferPool.sol is a **non upgradeable** ERC20Permit token. 
<!-- 
<sub>The ERC-20 permit feature is an extension to the ERC-20 standard that allows token holders to approve transfers without the need for two separate transactions. </sub> -->

It takes ETH deposits from stakers and mints `pufETH` ERC20 token in return. This can be achieved in 2 ways:
- Triggering a payable `receive()` function on this smart contract
- Calling `depositETH()` and sending the ETH along with it

Rewards / donations go through the `depositETHWithoutMinting()` function. This function will not mint any `pufETH` in return.
Depositing ETH through this function will eventually change the exchange rate between ETH and pufETH, making it so that for 1 pufETH you will be able to get more ETH in return. Withdrawals and exchanging of `pufETH` to ETH is possible through our [WithdrawalPool](./WithdrawalPool.md) smart contract or any third party exchange.

The [Guardians](./Guardians.md) are responsible for reporting the values used for calculation of the exchange rate [PufferPoolStorage](../src//struct/PufferPoolStorage.sol). Those values are stored on-chain within our main [PufferProtocol smart contract](../src/PufferProtocolStorage.sol)

PufferPool inherits from AbstractVault.sol which enables it to transfer any ERC20, ERC721, ERC1151 tokens to the PufferTreasury (with an exception to `pufETH`). This enables us to recover tokens sent to this contract by mistake.