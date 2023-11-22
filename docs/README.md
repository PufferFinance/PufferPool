# Puffer Protocol Docs

The Puffer Protocol enables anyone to run a validator node with a refundable bond of just 2 ETH and an additional payment for the desired operation time, known as a smoothing commitment. If Intel SGX or another Trusted Execution Environment (TEE) is utilized, the bond requirement is reduced to 1 ETH. The liquidity required to operate these validator nodes is provided by stakers who can stake ETH into the [PufferPool.sol](../src/PufferPool.sol) smart contract. In exchange, stakers receive pufETH, an asset that appreciates in value as the protocol generates rewards.

## Dependencies

All of our smart contract inherit from **AccessManaged | AccessManagedUpgradeable**

- [Openzeppelin smart contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)
    - AccessManager
    - AccessManaged
    - ERC20
    - ERC20Permit
    - ERC1967Proxy
    - UpgradeableBeacon
    - ECDSA
    - MerkleProof
    - MessageHashUtils
    - Strings
- [Openzeppelin upgradeable smart contracts](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable)
    - AccessManagedUpgradeable
    - UUPSUpgradeable
    - Initializable
- [Solady](https://github.com/Vectorized/solady)
    - FixedPointMathLib
    - SafeTransferLib
- [EigenLayer](https://github.com/Layr-Labs/eigenlayer-contracts)


## System components:

### [PufferProtocol](./PufferProtocol.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferProtocolStorage.sol`](../src/interface/IPufferProtocolStorage.sol) | Singleton | / | YES | / |
| [`IPufferProtocol.sol`](../src/interface/IPufferProtocol.sol) | Singleton | / | YES | / |
| [`PufferProtocolStorage.sol`](../src/PufferProtocolStorage.sol) | Singleton | UUPS Proxy | YES | / |
| [`PufferProtocol.sol`](../src/PufferProtocol.sol) | Singleton | UUPS Proxy | NO | / |

These contracts define the main entry point for the Puffer Protocol. They allow users to:

* Register validator public keys
* Deposit an ETH bond, which gets converted to pufETH and held within the [`PufferProtocol.sol`](../src/PufferProtocol.sol) contract 
* Pay the initial smoothing commitment, and also additional smoothing commitments to extend the duration of running their validator node
* Receive 32 provisioned ETH to run a validator node
* Stop running their validator node and retrieve their bond

The protocol also utilizes these smart contracts to perform important functions, such as:

* Proof of Reserves, AKA the amount of ETH backing pufETH
* Proof of Full Withdrawls, required for NoOps to be able to retrieve their bond after they have finished validating
* Create new Puffer Strategies, which will include various mixes of AVSs that NoOps can decide to opt into, depending on risk/reward preferences
* Store information about validator nodes and protocol state variables controlled by governance, such as the ratio at which withdrawn ETH is split between the [PufferPool](../src/PufferPool.sol) and [WithdrawalPool](../src/WithdrawalPool.sol) smart contracts

See full documentation in [./PufferProtocol.md](./PufferProtocol.md)

### [Guardians](./Guardians.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IGuardianModule.sol`](../src/interface/IGuardianModule.sol) | Singleton | / | YES | / |
| [`IEnclaveVerifier.sol`](../src/interface/IEnclaveVerifier.sol) | Singleton | / | YES |/ |
| [`EnclaveVerifier.sol`](../src/EnclaveVerifier.sol) | Singleton | NO | YES | / |
| [`GuardianModule.sol`](../src/GuardianModule.sol) | Singleton | NO | NO | / |
| [`{Safe} Guardians`](https://safe.global/) | {Safe} multisig | YES | NO | / |

The Guardians operate a [Safe multisig](https://github.com/safe-global/safe-contracts) and are a collective of respected community members who are deeply aligned with Ethereum's principles and values. They perform some trusted operations for our protocol, including:

* Reporting the amount of ETH backing pufETH
* Ejecting validators

See full documentation in [./Guardians.md](./Guardians.md)

### [Strategies](./Strategies.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferStrategy.sol`](../src/interface/IPufferStrategy.sol) | Singleton | / | YES | / |
| [`NoRestakingStrategy.sol`](../src/NoRestakingStrategy.sol) | Singleton | NO | NO | / |
| [`PufferStrategy.sol`](../src/PufferStrategy.sol) | [Beacon Proxy](https://docs.openzeppelin.com/contracts/5.x/api/proxy#BeaconProxy) | YES | NO | / |

Each Puffer Strategy refers to a specific set of AVSs for which all Puffer NoOps participating in that strategy must delegate their funds to running. Each validator node must choose exactly one Puffer Strategy to participate in, based on desired risk/reward preferences. The safest Puffer Strategy is the [NoRestakingStrategy](../src/NoRestakingStrategy.sol), which includes no AVSs. Validator nodes in this strategy only perform Ethereum consensus.

See full documentation in [./PufferStrategy.md](./PufferStrategy.md)

### [PufferPool](./PufferPool.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- |  -------- |
| [`TokenRescuer.sol`](../src/TokenRescuer.sol) | Singleton | NO | Yes | / |
| [`IPufferPool.sol`](../src/interface/IPufferPool.sol) | Singleton | NO | Yes | / |
| [`PufferPool.sol`](../src/PufferPool.sol) | Singleton | NO | / | / |

The [PufferPool](../src/PufferPool.sol) contract is where the main funds are held before provisioning validators. Stakers deposit ETH into this contract in exchange for pufETH. Protocol rewards may also be sent to this contract, which will ultimately appreciate the value of pufETH.

See full documentation in [./PufferPool.md](./PufferPool.md)

### [WithdrawalPool](./WithdrawalPool.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- |  -------- |
| [`IWithdrawalPool.sol`](../src/interface/IWithdrawalPool.sol) | Singleton | NO | YES | / |
| [`WithdrawalPool.sol`](../src/WithdrawalPool.sol) | Singleton | NO | / | / |

pufETH holders who wish to exchange their holdings for ETH may do so via the [WithdrawalPool](../src/WithdrawalPool.sol) contract, given there is enough liquidity to fulfill the exchange. This contract receives funds when Puffer NoOps discontinue running their validator nodes and return the ETH back to the protocol. Some of this ETH enters the [WithdrawalPool](../src/WithdrawalPool.sol) contract according to a ratio determined by governance. 

See full documentation in [./WithdrawalPool.md](./WithdrawalPool.md)
