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

#### High-level Concepts

This document organizes methods according to the following themes (click each to be taken to the relevant section):
* TODO
* [Guardian Functions](#guardian-functions)
* [Enclave Verifier Functions](#enclave-verifier-functions)

#### Important state variables

* TODO

#### Helpful definitions

* `bytes32 internal _mrenclave`: This value is a unique identifier for an SGX enclave, which is generated based on info within the enclave via hashing. AKA the Enclave Identity
* `bytes32 internal _mrsigner`: This value is a signature for the enclave, provided by an authority, which does not change even when the enclave is updated, unlike the mrenclave value. AKA the Signing Identity. This value will be the same for all enclaves signed with the same authority

---

### Guardian Functions

#### `setGuardianEnclaveMeasurements`

```solidity
function setGuardianEnclaveMeasurements(bytes32 newMrenclave, bytes32 newMrsigner) external
```

This function sets values for `mrEnclave` and `mrSigner` to the specified values

*Effects*: 
* Changes the following internal variables used for Intel SGX: `bytes32 internal _mrsigner` and `bytes32 internal _mrenclave`

*Requirements*:
* May only be called by Guardians

`validateGuardianSignatures`

```solidity
function validateGuardianSignatures(
    bytes memory pubKey,
    bytes calldata signature,
    bytes32 depositDataRoot,
    bytes calldata withdrawalCredentials,
    bytes[] calldata guardianEnclaveSignatures
)
```

Validates that the Guardians' enclaves have signed the particular data

*Effects*:
* N/A; View function

*Requirements*: 
* The signatures must be valid
* The required threshold of valid number of signatures must be met

`getMessageToBeSigned`

```solidity
function getMessageToBeSigned(
    bytes memory pubKey,
    bytes calldata signature,
    bytes calldata withdrawalCredentials,
    bytes32 depositDataRoot
) external pure returns (bytes32)
```

Returns the message that the Guardians' enclaves must sign

*Effects*:
* N/A; View function

*Requirements*: 
* N/A; Callable by anyone

`rotateGuardianKey`

```solidity
function rotateGuardianKey(uint256 blockNumber, bytes calldata pubKey, RaveEvidence calldata evidence) external
```

function description TODO

*Effects*:


*Requirements*:
* May only be called by Guardians

---

### Enclave Verifier Functions