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
| [`{Safe} Guardians`](https://safe.global/) | {Safe} multisig | YES | NO | / |

### [Strategies](./Strategies.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IPufferStrategy.sol`](../src/interface/IPufferStrategy.sol) | Singleton | / | YES | / |
| [`NoRestakingStrategy.sol`](../src/NoRestakingStrategy.sol) | Singleton | NO | NO | / |
| [`PufferStrategy.sol`](../src/PufferStrategy.sol) | [Beacon Proxy](https://docs.openzeppelin.com/contracts/5.x/api/proxy#BeaconProxy) | YES | NO | / |

### [PufferPool](./PufferPool.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- |  -------- |
| [`TokenRescuer.sol`](../src/TokenRescuer.sol) | Singleton | NO | Yes | / |
| [`IPufferPool.sol`](../src/interface/IPufferPool.sol) | Singleton | NO | Yes | / |
| [`PufferPool.sol`](../src/PufferPool.sol) | Singleton | NO | / | / |

### [WithdrawalPool](./WithdrawalPool.md)

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- |  -------- |
| [`IWithdrawalPool.sol`](../src/interface/IWithdrawalPool.sol) | Singleton | NO | YES | / |
| [`WithdrawalPool.sol`](../src/WithdrawalPool.sol) | Singleton | NO | / | / |
