# PufferPool

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- |  -------- |
| [`AbstractVault.sol`](../src/AbstractVault.sol) | Singleton | NO | Yes | / |
| [`IPufferPool.sol`](../src/interface/IPufferPool.sol) | Singleton | NO | Yes | / |
| [`PufferPool.sol`](../src/PufferPool.sol) | Singleton | NO | / | / |

PufferPool.sol is a **non upgradeable** ERC20Permit token. 
<!-- 
<sub>The ERC-20 permit feature is an extension to the ERC-20 standard that allows token holders to approve transfers without the need for two separate transactions. </sub> -->

It takes ETH deposits from stakers and mints `pufETH` ERC20 token in return. This can be achieved in 2 ways:
- Triggering a payable `receive()` function on this smart contract
- Calling `depositETH()` and sending the ETH along with it

Rewards / donations go through the `depositETHWithoutMinting()` function. This function will not mint any `pufETH` in return.
Depositing ETH through this function will eventually change the exchange rate between ETH and pufETH, making it so that for 1 pufETH you will be able to get more ETH in return. Withdrawals and exchanging of `pufETH` to ETH is possible through our [WithdrawalPool](./WithdrawalPool.md) smart contract or any third party exchange.

The [Guardians](./Guardians.md) are responsible for reporting the values used for calculation of the exchange rate: [PufferPoolStorage](../src/struct/PufferPoolStorage.sol). Those values are stored, and can be accessed, on-chain within our main [PufferProtocol smart contract](../src/PufferProtocolStorage.sol)

PufferPool inherits from AbstractVault.sol which enables it to transfer any ERC20, ERC721, ERC1151 tokens to the PufferTreasury (with an exception to `pufETH`). This enables us to recover tokens sent to this contract by mistake.

#### High-level Concepts

This document organizes methods according to the following themes (click each to be taken to the relevant section):
* [Depositing ETH](#depositing-eth)
* [Other Functions](#other-functions)

#### Important state variables

The PufferPool accesses state variables within [PufferPoolStorage](../src/struct/PufferPoolStorage.sol) to determine the exchange rate between ETH and pufETH. These are:

* `uint256 ethAmount`: Keeps track of the ETH within the protocol, not locked in the beacon chain deposit contract
* `uint256 lockedETH`: The amount of ETH within the protocol, but locked in the beacon chain deposit contract
* `uint256 pufETHTotalSupply`: The total outstanding amount of pufETH tokens
* `uint256 lastUpdate`: The block number upon which these values were last updated

#### Helpful definitions

* `pufETH`: A token which is minted upon ETH deposits to the PufferPool. It is an appreciating asset which grows as the protocol earns rewards. NoOp bonds are held in pufETH

---

### Depositing ETH

#### `depositETH`

```solidity
function depositETH() external payable returns (uint256)
```

This function allows the caller to send ETH to the `PufferPool` contract, minting pufETH in return. This function is also called whenever ETH is sent to the `PufferPool` contract, triggered via the `receive()` function.

*Effects*:
* Mints new pufETH and sends it to the caller

*Requirements*:
* N/A callable by anyone

#### `depositETHWithoutMinting`

```solidity
function depositETHWithoutMinting() public payable
```

This is a special function that allows ETH to be sent to the `PufferPool` contract without minting any new pufETH. This is used to distribute rewards and appreciate the value of pufETH by increasing the ETH backing pufETH, but not increasing the amount of outstanding pufETH.

*Effects*: 
* Adds more ETH to the `PufferPool` contract without minting any new pufETH
* Increases the exchange rate value of pufETH relative to ETH, effectively appreciating the price of pufETH

*Requirements*:
* N/A callable by anyone

---

### Other Functions

#### `burn`

```solidity
function burn(address owner, uint256 pufETHAmount) external
```

This function allows Guardians or the Protocol to burn a NoOp's pufETH bond if their validator has exited the beacon chain with a balance less than 32 ETH

*Effects*:
* Removes (burns) the specified amount of pufETH held by the owner

*Requirements*: 
* Only callable by Guardians or the PufferProtocol smart contracts

#### `recoverERC20`

```solidity
function recoverERC20(address token) external
```

Allows tokens which were accidentally sent to the `PufferPool` to be recovered (sent) to the Treasury contract. PufferPool inherits from TokenRescuer.sol which enables it to transfer any ERC20, ERC721, ERC1151 tokens to the PufferTreasury (with an exception to `pufETH`). This enables us to recover tokens sent to this contract by mistake.

*Effects*:
* Sends the totality of the specified token from the `PufferPool` contract to the Treasury contract

*Requirements*:
* N/A Callable by anyone
