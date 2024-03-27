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
| [`IPufferProtocol.sol`](../src/interface/IPufferProtocol.sol) | Interface | / | YES | / |
| [`PufferProtocolStorage.sol`](../src/PufferProtocolStorage.sol) | Singleton | UUPS Proxy | YES | / |
| [`PufferProtocol.sol`](../src/PufferProtocol.sol) | Singleton | UUPS Proxy | NO | / |

### [GuardianModule](./GuardianModule.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IGuardianModule.sol`](../src/interface/IGuardianModule.sol) | Interface | / | YES | / |
| [`IEnclaveVerifier.sol`](../src/interface/IEnclaveVerifier.sol) | Interface | / | YES |/ |
| [`EnclaveVerifier.sol`](../src/EnclaveVerifier.sol) | Singleton | NO | YES | / |
| [`GuardianModule.sol`](../src/GuardianModule.sol) | Singleton | NO | NO | / |

### [ValidatorTicket](./ValidatorTicket.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IValidatorTicket.sol`](../src/interface/IValidatorTicket.sol) | Interface | / | YES | / |
| [`ValidatorTicket.sol`](../src/ValidatorTicket.sol) | Singleton | UUPS Proxy | NO | / |

### [PufferOracleV2](./PufferOracleV2.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferOracleV2.sol`](../lib/pufETH/src/interface/IPufferOracleV2.sol) | Interface | / | YES | / |
| [`PufferOracleV2.sol`](../src/PufferOracleV2.sol) | Singleton | / | NO | / |

### [PufferModuleManager](./PufferModuleManager.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferModuleManager.sol`](../src/interface/IPufferModuleManager.sol) | Interface | / | YES | / |
| [`PufferModuleManager.sol`](../src/PufferModuleManager.sol) | Singleton | UUPS Proxy | NO | / |


### [PufferModules](./PufferModule.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferModule.sol`](../src/interface/IRestakingOperator.sol) | Interface | / | YES | / |
| [`PufferModule.sol`](../src/PufferModule.sol) | [Beacon Proxy](https://docs.openzeppelin.com/contracts/5.x/api/proxy#BeaconProxy) | YES | NO | / |

### [RestakingOperators](./RestakingOperator.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferModule.sol`](../src/interface/IPufferModule.sol) | Interface | / | YES | / |
| [`PufferModule.sol`](../src/RestakingOperator.sol) | [Beacon Proxy](https://docs.openzeppelin.com/contracts/5.x/api/proxy#BeaconProxy) | YES | NO | / |

## System overview
![System overview](image.png)