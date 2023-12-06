# PufferProtocol

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferProtocolStorage.sol`](../src/interface/IPufferProtocolStorage.sol) | Singleton | / | YES | / |
| [`IPufferProtocol.sol`](../src/interface/IPufferProtocol.sol) | Singleton | / | YES | / |
| [`PufferProtocolStorage.sol`](../src/PufferProtocolStorage.sol) | Singleton | UUPS Proxy | YES | / |
| [`PufferProtocol.sol`](../src/PufferProtocol.sol) | Singleton | UUPS Proxy | NO | / |

#### Overview

The [PufferProtocol](../src/PufferProtocol.sol) contract is the main entry point for the Puffer Protocol. This contract allows Node Operators (NoOps) to register their public keys with the protocol, and they are subsequently provisioned 32 ETH in order to operate a validator. Registering requires depositing an ETH-denominated bond that is converted to pufETH upon deposit and held within the contract. A 1 ETH bond is required for NoOps running TEEs such as Intel SGX, otherwise a 2 ETH bond is required. An additional requirement to operate a validator is to pay a smoothing commitment, which allows operation of the validator for a certain amount of time, corresponding to the amount of smoothing commitment paid. NoOps may pay additional smoothing commitments in order to extend their validator's working duration. Note that, unlike the bond, smoothing commitments are non-refundable. 

The PufferProtocol contract also allows NoOps to stop their validators. Before a NoOp is provisioned 32 ETH, they may call the `stopRegistration()` function to cancel registration. Note that the NoOp will only receive back their bond in this case, not their smoothing commitment.

#### Proof of Reserves

Proof of reserves happen through this contract, as well as proof of full withdrawals. NoOps may submit proof of their full withdrawal in order to retrieve their bonded pufETH after they are finished validating, given that they have not been slashed or were inactive. If they were slashed, they do not receive back any of their bond. If they were inactive and lost some ETH from the originally provisioned 32, their bonded pufETH will be slashed by the corresponding amount, given the ETH to pufETH ratio at the time of exit. New Puffer modules involving various AVSs (or no AVS) may be created through this contract.

#### Provisioning Validators

This contract maintains a queue to provision validators for NoOps, and also stores other various information about NoOps and other variables within the protocol that are maintained by governance, for example, the ratio at which ETH enters the [WithdrawalPool](./WithdrawalPool.md) upon a NoOp withdrawing from the protocol.

#### High-level Concepts

This document organizes methods according to the following themes (click each to be taken to the relevant section):
* [Provisioning a Validator](#provisioning-a-validator)
* [Withdrawing from Protocol](#withdrawing-from-protocol)
* [Protocol Maintenance](#protocol-maintenance)

#### Important state variables

* `uint256 internal constant _BURST_THRESHOLD`: Used to cap our pool at 22% of ETH staked, in order to promote and maintain a decentralized Ethereum

* `bytes32[] moduleWeights`: Defines how to provision queued validators in a weighted round-robin across the various modules

* `uint256 withdrawalPoolRate`: Defines the ratio at which returned validator ETH enters the [WithdrawalPool](./WithdrawalPool.md) smart contract

* `uint72 protocolFeeRate`: Defines the percentage of rewards earned by operation of Puffer that return to the protocol to cover maintenance costs

* `uint72 guardiansFeeRate`: Defines the percentage of rewards earned by operation of Puffer that return to the Guardians to ensure their continued honest participation

* `mapping(bytes32 moduleName => uint256 pendingValidatorIndex) pendingValidatorIndicies`: Keeps track of validators waiting to be provisioned to enter the corresponding module. Note that the validator index here is different from the beacon chain validator index

* `mapping(bytes32 moduleName => mapping(uint256 index => Validator validator)) validators`: Keeps track of current validators running within the corresponding module

* `mapping(uint256 blockNumber => bytes32 root) fullWithdrawalsRoots`: These are merkle tree roots that are posted every set number of blocks by the Guardians. These are necessary for NoOps to prove their full withdrawal via merkle proof and retrieve their bond

#### Helpful definitions

* Module: A defined set of AVSs that a Puffer NoOp may choose to delegate their funds to running / maintaining. NoOps must choose exactly one module per each validator they run, upon entering the Puffer Protocol
* Smoothing Commitment: A non-refundable payment NoOps must provide in order to run their validator for a set period of time. NoOps may make a large smoothing commitment to gain the rights to operate their validator for longer, or can make top-up payments anytime.

---

### Provisioning a Validator

#### `registerValidatorKey`

```solidity
function registerValidatorKey(ValidatorKeyData calldata data, bytes32 moduleName, uint256 numberOfMonths)
    external
    payable
```

This function initiates the process of provisioning a new validator for a NoOp. The NoOp must pay the smoothing commitment amount, and a bond of 2 ETH (1 ETH if using SGX or other TEE) upon calling this function

*Effects*:
* Smoothing commitment is taken from the NoOp and deposited into the pool as rewards
* ETH bond is taken from the NoOp and deposited into the pool, also minting a corresponding amount of pufETH, which is locked in the `PufferProtocol.sol` smart contract until the NoOp's validator exits
* Information about the new validator is saved on-chain
* The validator is pushed onto an on-chain queue of pending validators, waiting to be provisioned

*Requirements*:
* Caller must provide a valid public key that is not currently registered with the protocol
* Caller must submit valid RAVE evidence if using SGX or other TEE
* Caller must provide valid ETH bond amount (1 ETH with SGX or other TEE, otherwise 2 ETH)
* Caller must provide number of months desired to operate validator, along with corresponding amount of ETH to cover smoothing commitment

#### `registerValidatorKeyPermit`

```solidity
function registerValidatorKeyPermit(
        ValidatorKeyData calldata data,
        bytes32 moduleName,
        uint256 numberOfMonths,
        Permit calldata permit
    ) external payable
```

This function initates the process of provisioning a new validator for a NoOp, similar to the above, except this function takes pufETH instead of ETH for the bond payment. The amount of pufETH supplied must match the bond amount in ETH value, according to the protocol's current exchange rate of ETH to pufETH.

*Effects*
* Smoothing commitment is taken from the NoOp and deposited into the pool as rewards
* pufETH is taken from the NoOp and locked in the `PufferProtocol.sol` smart contract until the NoOp's validator exits
* Information about the new validator is saved on-chain
* The validator is pushed onto an on-chain queue of pending validators, waiting to be provisioned

*Requirements*
* Caller must either provide permit data to allow transferring of the ERC20 pufETH token. Otherwise caller must have approved the amount of pufETH token to be accepted by the smart contract via the [ERC20 `approve()` function](https://docs.openzeppelin.com/contracts/5.x/api/token/erc20#IERC20-approve-address-uint256-)
* Caller must submit valid RAVE evidence if using SGX or other TEE
* Caller must provide valid pufETH bond amount according to protocol's ETH to pufETH exchange ratio (1 ETH equivalent with SGX or other TEE, otherwise 2 ETH equivalent)
* Caller must provide number of months desired to operate validator, along with corresponding amount of ETH to cover smoothing commitment. (Note that while bond may be in pufETH, smoothing commitment is still paid in ETH)

#### `provisionNode`

```solidity
function provisionNode(bytes[] calldata guardianEnclaveSignatures) external
```

Provisions the next validator that is in line for provisioning, given the `guardianEnclaveSignatures` are valid

*Effects*:
* Sets the next validator's status to ACTIVE
* Increments the index of the next node to provision for the module this node was provisioned for
* Increments the module selection index
* Transfers 32 ETH from the pool into the module contract address
* Stakes the 32 ETH on the beacon chain, either directly or via Eigenpod, or any other method defined by the particular module contract

*Requirements*
* The Guardians must have provided valid signatures in order to provision this node
* The PufferPool contract must have enough ETH to fulfill this request

#### `extendCommitment`

```solidity
function extendCommitment(bytes32 moduleName, uint256 validatorIndex, uint256 numberOfMonths) external payable
```

Allows NoOps to pay additional smoothing commitments in order to be able to continue running their validators for additional time

*Effects*:
* Extends NoOp's allowed time to operate this valdiator by the specified number of months
* Takes the corresponding amount of ETH from the caller and distributes it amongst the Treasury, PufferPool, WithdrawalPool, and the Guardians by the ratios set by the protocol / governance

*Requirements*
* Must supply a `numberOfMonths` less than 13
* Must supply the corresponding amount of ETH for the specified duration of time

---

### Withdrawing from Protocol

#### `stopRegistration`

```solidity
function stopRegistration(bytes32 moduleName, uint256 validatorIndex) external
```

Allows a NoOp to stop their pending provisioning of a validator and exit themselves from the queue

*Effects*:
* Updates the status of this validator in the queue to DEQUEUED
* If this validator was next to be provisioned, increments the counter for next node to be provisioned
* Transfers the bonded ETH back to the NoOp

*Requirements*:
* Caller must be the corresponding NoOp for this pending validator
* Validator must have pending status in the queue

#### `stopValidator`

```solidity
function stopValidator(
    bytes32 moduleName,
    uint256 validatorIndex,
    uint256 blockNumber,
    uint256 withdrawalAmount,
    bool wasSlashed,
    bytes32[] calldata merkleProof
) external
```

Allows anyone to submit a merkle proof proving a validator's full withdrawal from the beacon chain. If the validator was not slashed, this will return the full amount of the bond back to the NoOp. If the validator was slashed, no bond amount will be returned. If the balance of the validator is less than 32 ETH, the difference will be taken out of the bond before returning it to the NoOp.

*Effects*:
* Delete unused information regarding the validator from on-chain
* Change the validator to EXITED status
* Return the validator's bond to the NoOp, if they were not slashed
* Burn the corresponding amount from the validator's bond if the validator's balance is less than 32 ETH

*Requirements*:
* Validator must be in ACTIVE status
* Submitted merkle proof must be valid

---

### Protocol Maintenance

#### `skipProvisioning`

```solidity
function skipProvisioning(bytes32 moduleName) external
```

Skips provisioning of a validator, making the next node in the queue the next node to provision. Returns the skipped validator's bond back to the NoOp.

*Effects*:
* Changes the status of the skipped vaidator node to SKIPPED
* Transfers the bond back to the NoOp corresponding to this skipped validator
* Increments the next to be provisioned node counter for the module corresponding to `moduleName`

*Requirements*:
* May only be called by Guardians

#### `postFullWithdrawalsRoot`

```solidity
function postFullWithdrawalsRoot(
    bytes32 root,
    uint256 blockNumber,
    address[] calldata modules,
    uint256[] calldata amounts
) external
```

Allows Guardians to post the merkle root for all full withdrawals that happened from the last time the root was posted up until `blockNumber`. This allows NoOps to prove when they have fully withdrawn their valdiator nodes in order to claim back their bond

*Effects*:
* Stores the new full withdrawal root on-chain, mapped to `blockNumber`
* Moves all full withdrawal ETH living on module contracts back to the PufferPool and WithdrawalPool, corresponding to the `withdrawalPoolRate`, set by governance

*Requirements*:
* Must be called by Guardians
* Must provide a full withdrawal amount per each module address passed into this function's parameters

#### `proofOfReserve`

```solidity
function proofOfReserve(uint256 ethAmount, uint256 lockedETH, uint256 pufETHTotalSupply, uint256 blockNumber) external
```

Allows Guardians to post the amount of ETH backing pufETH

*Effects*:
* Sets the state variables: `ethAmount`, `lockedEth`, `pufETHTotalSupply`, and `lastUpdate`
* Resets the count of validators that can join our protocol in an interval

*Requirements*:
* Must be called by Guardians
* Block number must be a finalized block (>= 64 blocks in the past)
* The provided block number must be greater than our update interval