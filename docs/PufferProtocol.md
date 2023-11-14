# PufferProtocol

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferProtocolStorage.sol`](../src/interface/IPufferProtocolStorage.sol) | Singleton | / | YES | / |
| [`IPufferProtocol.sol`](../src/interface/IPufferProtocol.sol) | Singleton | / | YES | / |
| [`PufferProtocolStorage.sol`](../src/PufferProtocolStorage.sol) | Singleton | UUPS Proxy | YES | / |
| [`PufferProtocol.sol`](../src/PufferProtocol.sol) | Singleton | UUPS Proxy | NO | / |

The [PufferProtocol](../src/PufferProtocol.sol) contract is the main entry point for the Puffer Protocol. This contract allows users to register their public keys with the protocol and receive 32 provisioned ETH in order to operate a validator node. In order to do so, they must deposit a bond, which is denominated in ETH, but is converted to pufETH upon deposit and held within the contract. A 1 ETH bond is required for NoOps running TEEs such as Intel SGX, otherwise a 2 ETH bond is required. An additional requirement to operate a validator is to pay a smoothing commitment, which allows operation of the validator for a certain amount of time, corresponding to the amount of smoothing commitment paid. Puffer NoOps may pay additional smoothing commitments here in order to extend the allowed duration of operating their validators. Note that, unlike the bond, smoothing commitments are not refunded, no matter the status of the validator. NoOps must interact with this contract in order to stop their validator nodes as well. Before a NoOp is provisioned 32 ETH, they may call the `stopRegistration()` function to cancel registration. Note that the NoOp will only receive back their bond in this case, not their smoothing commitment.

Proof of reserves happen through this contract, as well as proof of full withdrawals, which NoOps may submit in order to retrieve their bonded pufETH after they are finished validating, given that they have not been slashed or were inactive. If they were slashed, they do not receive back any of their bond. If they were inactive and lost some ETH from the originally provisioned 32, their bonded pufETH will be slashed by the corresponding amount, given the ETH to pufETH ratio at the time of exit. New Puffer strategies involving various AVSs (or no AVS) may be created through this contract.

Finally, this contract maintains a queue to provision validators for NoOps, and also stores other various information about NoOps and other variables within the protocol that are maintained by governance, for example, the ratio at which ETH enters the [WithdrawalPool](./WithdrawalPool.md) upon a NoOp withdrawing from the protocol.


#### High-level Concepts

This document organizes methods according to the following themes (click each to be taken to the relevant section):

#### Important state variables

* `bytes32[] strategyWeights`: Defines how to provision queued validators in a weighted round-robin across the various strategies

* `uint256 withdrawalPoolRate`: Defines the ratio at which returned validator ETH enters the [WithdrawalPool](./WithdrawalPool.md) smart contract

* `uint72 protocolFeeRate`: Defines the percentage of rewards earned by operation of Puffer that return to the protocol to cover maintenance costs

* `uint72 guardiansFeeRate`: Defines the percentage of rewards earned by operation of Puffer that return to the Guardians to ensure their continued honest participation

* `mapping(bytes32 strategyName => uint256 pendingValidatorIndex) pendingValidatorIndicies`: Keeps track of validators waiting to be provisioned to enter the corresponding strategy. Note that the validator index here is different from the beacon chain validator index

* `mapping(bytes32 strategyName => mapping(uint256 index => Validator validator)) validators`: Keeps track of current validators running within the corresponding strategy

* `mapping(uint256 blockNumber => bytes32 root) fullWithdrawalsRoots`: These are merkle tree roots that are posted every set number of blocks by the Guardians. These are necessary for NoOps to prove their full withdrawal via merkle proof and retrieve their bond

#### Helpful definitions

* Strategy: A defined set of AVSs that a Puffer NoOp may choose to delegate their funds to running / maintaining. NoOps must choose exactly one strategy per each validator they run, upon entering the Puffer Protocol.