# Overview

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
    - Address
    - SafeCast
- [Openzeppelin upgradeable smart contracts](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable)
    - AccessManagedUpgradeable
    - UUPSUpgradeable
    - Initializable
- [EigenLayer](https://github.com/Layr-Labs/eigenlayer-contracts)


## System components:

### [PufferProtocol](./PufferProtocol.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferProtocolStorage.sol`](../src/interface/IPufferProtocolStorage.sol) | Singleton | / | YES | / |
| [`IPufferProtocol.sol`](../src/interface/IPufferProtocol.sol) | Singleton | / | YES | / |
| [`PufferProtocolStorage.sol`](../src/PufferProtocolStorage.sol) | Singleton | UUPS Proxy | YES | / |
| [`PufferProtocol.sol`](../src/PufferProtocol.sol) | Singleton | UUPS Proxy | NO | / |

### [Guardians](./Guardians.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IGuardianModule.sol`](../src/interface/IGuardianModule.sol) | Singleton | / | YES | / |
| [`IEnclaveVerifier.sol`](../src/interface/IEnclaveVerifier.sol) | Singleton | / | YES |/ |
| [`EnclaveVerifier.sol`](../src/EnclaveVerifier.sol) | Singleton | NO | YES | / |
| [`GuardianModule.sol`](../src/GuardianModule.sol) | Singleton | NO | NO | / |

### [PufferModuleManager](./PufferModuleManager.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`PufferModuleManager.sol`](../src/PufferModuleManager.sol) | Singleton | UUPS Proxy | NO | / |


### [PufferModules](./PufferModules.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferModule.sol`](../src/interface/IRestakingOperator.sol) | Singleton | / | YES | / |
| [`PufferModule.sol`](../src/PufferModule.sol) | [Beacon Proxy](https://docs.openzeppelin.com/contracts/5.x/api/proxy#BeaconProxy) | YES | NO | / |

### [RestakingOperators](./RestakingOperators.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferModule.sol`](../src/interface/IPufferModule.sol) | Singleton | / | YES | / |
| [`PufferModule.sol`](../src/RestakingOperator.sol) | [Beacon Proxy](https://docs.openzeppelin.com/contracts/5.x/api/proxy#BeaconProxy) | YES | NO | / |

