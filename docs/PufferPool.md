# PufferPool

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- |  -------- |
| [`AbstractVault.sol`](../src/AbstractVault.sol) | Singleton | NO | Yes | / |
| [`IPufferPool.sol`](../src/interface/IPufferPool.sol) | Singleton | NO | Yes | / |
| [`PufferPool.sol`](../src/PufferPool.sol) | Singleton | NO | / | / |

PufferPool.sol is a **non upgradeable** ERC20Permit token. 
<!-- 
<sub>The ERC-20 permit feature is an extension to the ERC-20 standard that allows token holders to approve transfers without the need for two separate transactions. </sub> -->

The payable `depositETH()` function allows stakers to deposit ETH and mints the `pufETH` ERC20 token in return.

The `depositETHWithoutMinting()` function is used in the case where ETH is deposited to the PufferPool but no pufETH is minted in return. This is needed for depositing Smoothing Commitments and restaking rewards.

As ETH is deposited and pufETH is minted, the exchange rate between ETH and pufETH will change. Note that this doesn't happen immediately, but will be reflected the next time Proof of Reserves is posted. Assuming rewards exceed penalties, this means 1 pufETH will become redeemable for more than 1 ETH. To handle redemptions, the WithdrawalPool is used to burn pufETH to receive ETH, assuming sufficient ETH liquidity. Alternatively, since pufETH is a liquid ERC-20 token, it can be exchanged on a secondary market.

Withdrawals and exchanging of `pufETH` to ETH is possible through our [WithdrawalPool](./WithdrawalPool.md) smart contract or any third party exchange.

The [Guardians](./Guardians.md) are responsible for reporting the values used for calculation of the exchange rate: [PufferPoolStorage](../src/struct/PufferPoolStorage.sol). Those values are stored, and can be accessed, on-chain within our main [PufferProtocol smart contract](../src/PufferProtocolStorage.sol)

PufferPool inherits from AbstractVault.sol which enables it to transfer any ERC20, ERC721, ERC1151 tokens to the PufferTreasury. This enables us to recover tokens sent to this contract by mistake.

#### High-level Concepts

This document organizes methods according to the following themes (click each to be taken to the relevant section):
* [Depositing ETH](#depositing-eth)
* [Other Functions](#other-functions)

#### Important state variables

The PufferPool accesses state variables within [PufferPoolStorage](../src/struct/PufferPoolStorage.sol) to determine the exchange rate between ETH and pufETH. These are:

* `uint256 ethAmount`: Keeps track of on-chain ETH pertaining to the protocol
* `uint256 lockedETH`: The amount of beacon chain ETH pertaining to the protocol
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

This function allows the caller to send ETH to the `PufferPool` contract, minting pufETH in return.

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
* Increases the exchange rate value of pufETH relative to ETH, effectively appreciating the price of pufETH. Note: The exchange rate isn't directly changed here upon this function call, but upon next time Proof of Reserves is calculated and the exchange rate is posted

*Requirements*:
* N/A callable by anyone

---

### Other Functions

#### `burn`

```solidity
function burn(uint256 pufETHAmount) external
```

This function allows pufETH to be burned upon redemption of ETH in exchange for pufETH.

*Effects*:
* Removes (burns) the specified amount of pufETH held by the caller

*Requirements*: 
* N/A callable by anyone

#### `recoverERC20`

```solidity
function recoverERC20(address token) external
```

Allows tokens which were accidentally sent to the `PufferPool` to be recovered (sent) to the Treasury contract. PufferPool inherits from TokenRescuer.sol which enables it to transfer any ERC20, ERC721, ERC1151 tokens to the PufferTreasury. This enables us to recover tokens sent to this contract by mistake.

*Effects*:
* Sends the totality of the specified token from the `PufferPool` contract to the Treasury contract

*Requirements*:
* N/A Callable by anyone
