# Guardians

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IGuardianModule.sol`](../src/interface/IGuardianModule.sol) | Singleton | / | YES | / |
| [`IEnclaveVerifier.sol`](../src/interface/IEnclaveVerifier.sol) | Singleton | / | YES |/ |
| [`EnclaveVerifier.sol`](../src/EnclaveVerifier.sol) | Singleton | NO | YES | / |
| [`GuardianModule.sol`](../src/GuardianModule.sol) | Singleton | NO | NO | / |
| [`{Safe} Guardians`](https://safe.global/) | {Safe} multisig | YES | NO | / |

Guardians is a [Safe multisig](https://github.com/safe-global/safe-contracts). They play a crucial role in our system and are a collective of respected community members who are deeply aligned with Ethereum's principles and values.

On top of that, we are deploying and enabling [GuardianModule.sol](../src/GuardianModule.sol).
Our guardians have their own EOAs (Externally Owned Accounts) that are owners of the Safe, and at the same time, they are running [enclaves](https://en.wikipedia.org/wiki/Trusted_execution_environment) and creating a wallet inside of an enclave. The wallets from the enclave are used to sign data that the enclave produces. GuardianModule is used to ensure that the guardians are:
- Using a trusted execution environment
- Validating the Guardian's signatures coming from the enclaves

The Guardian module allows guardians to change their enclave address to a new enclave address. For this purpose, we are using [EnclaveVerifier](./EnclaveVerifier.md). It ensures that the guardians are using enclaves.

The roles of the guardians are:
- Reporting the amount of ETH backing pufETH
- Ejecting validators

For some parts of our system, guardians can use a normal Safe multisig transaction to interact with the Puffer smart contracts, while for others, we require signatures coming from the guardians' enclave wallets.
