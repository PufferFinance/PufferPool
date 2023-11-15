# PufferStrategy

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferStrategy.sol`](../src/interface/IPufferStrategy.sol) | Singleton | / | YES | / |
| [`NoRestakingStrategy.sol`](../src/NoRestakingStrategy.sol) | Singleton | NO | NO | / |
| [`PufferStrategy.sol`](../src/PufferStrategy.sol) | [Beacon Proxy](https://docs.openzeppelin.com/contracts/5.x/api/proxy#BeaconProxy) | YES | NO | / |

The PufferStrategy contract defines a template for Puffer strategies. A strategy refers to the specific set of AVSs for which all Puffer NoOps participating in the strategy must delegate their funds to running. This set of AVSs may be empty, as in the case of the [NoRestakingStrategy](../src/NoRestakingStrategy.sol), in which the totality of the funds in this contract are committed solely to performing ETH validation, and no funds are delegated to any AVSs.

#### High-level Concepts

This document organizes methods according to the following themes (click each to be taken to the relevant section):
* [Opting into a Strategy](#opting-into-a-strategy)
* [Retrieving Rewards](#retrieving-rewards)
* [Protocol Functions](#protocol-functions)

#### Important state variables

* `function NAME() external view returns (bytes32)`: Each Strategy will have a unique name, acting as its identifier

#### Helpful definitions

* Strategy: A defined set of AVSs that a Puffer NoOp may choose to delegate their funds to running / maintaining. NoOps must choose exactly one strategy per each validator they run, upon entering the Puffer Protocol
* `mapping(uint256 blockNumber => bytes32 root) public rewardsRoots`: Keeps track of the merkle tree roots posted by Guardians to allow NoOps to prove and retrieve rewards
* `mapping(uint256 blockNumber => mapping(bytes32 pubKeyHash => bool claimed)) public claimedRewards`: Mapping that stores which validators have claimed the rewards for a certain blockNumber
* `uint256 internal _lastProofOfRewardsBlockNumber`: The last block number for when the rewards root was posted

---

### Opting into a Strategy

#### `callStake`

```solidity
function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot) external payable
```

This function serves as the entry point for a NoOp to opt into a strategy and begin staking through this strategy. The ETH funds sent upon calling this function will eventually end up staked on the beacon chain, either though an EigenPod, or other means, depending on the type of strategy.

*Effects*:
* Will create a new deposit on the beacon chain, and initiate starting a new validator node
* May deploy an EigenPod contract, depending on the strategy

*Requirements*:
* This function must be called with 32 ETH

---

## `PufferStrategy.sol`

### Retrieving Rewards

#### `collectNonRestakingRewards`

```solidity
function collectNonRestakingRewards() external
```

This function allows NoOps to claim their consensus rewards, earned by their validator node operating within this strategy

*Effects*:
* Will withdraw the corresponding amount of ETH from this strategy, sending it to the NoOp's address

*Requirements*:
* Caller must submit a valid merkle proof to prove the due rewards

#### `collectRestakingRewards`

```solidity
function collectRestakingRewards() external
```

This function allows NoOps to claim their rewards earned through restaking from the AVSs defined in this strategy

*Effects*:
* Will withdraw the corresponding amount of ETH from this strategy, sending it to the NoOp's address

*Requirements*:
* Caller must submit a valid merkle proof to prove the due rewards

## `NoRestakingStrategy.sol`

#### `collectRewards`

```solidity
function collectRewards(
    address node,
    bytes32 pubKeyHash,
    uint256[] calldata blockNumbers,
    uint256[] calldata amounts,
    bytes32[][] calldata merkleProofs
) external
```

This function allows NoOps to collect consensus rewards from the `NoRestakingStrategy` contract

*Effects*:
* Withdraws the corresponding amount of ETH from the `NoRestakingStrategy` contract, sending it to the specified NoOp address

*Requirements*:
* Anyone can call this function, given a valid merkle proof is passed to this function

---

### Protocol Functions

## `NoRestakingStrategy.sol`

#### `postRewardsRoot`

```solidity
function postRewardsRoot(bytes32 root, uint256 blockNumber) external
```

Allows Guardians to post the rewards merkle tree root so NoOps may prove and retrieve their rewards

*Effects*:
* Posts a new merkle tree root on-chain, mapped to the specified block number

*Requirements*:
* May only be called by Guardians
