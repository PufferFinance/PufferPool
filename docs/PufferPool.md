# PufferPool

PufferPool.sol is a **non upgradeable** ERC20Permit token. 
<!-- 
<sub>The ERC-20 permit feature is an extension to the ERC-20 standard that allows token holders to approve transfers without the need for two separate transactions. </sub> -->

It takes the ETH deposits from the Puffers and mints `pufETH` ERC20 token in return. That can be achieved in 2 ways:
- Triggering a payable `receive()` function on this smart contract
- Calling `depositETH()` and sending the ETH along with it

The rewards / donations are going through the `depositETHWithoutMinting()` function. This function will not mint any `pufETH` in return.
Depositing ETH through this function will eventually change the exchange rate between ETH and pufETH, making it so that for 1 pufETH you will be able to get more ETH in return. The withdrawals and exchanging of `pufETH` to ETH is happening through our [WithdrawalPool](./WithdrawalPool.md) smart contract or any third party exchange.

The [Guardians](./Guardians.md) are responsible for reporting the values used for calculation of the exchange rate [PufferPoolStorage](../src//struct/PufferPoolStorage.sol). Those values are stored in the storage of our main [PufferProtocol smart contract](../src/PufferProtocolStorage.sol)

PufferPool inherits from AbstractVault.sol which enables it to transfer any ERC20, ERC721, ERC1151 tokens to the PufferTreasury (with an exception to `pufETH`). This enables us to recover tokens sent to this contract by mistake.