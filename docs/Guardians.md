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
* [Guardian Functions](#guardian-functions)
* [Enclave Verifier Functions](#enclave-verifier-functions)

#### Important state variables

### Guardian Module

* `Safe public immutable GUARDIANS`: The SAFE multisig controlled by the Guardians
* `IEnclaveVerifier public immutable ENCLAVE_VERIFIER`: The Enclave Verifier smart contract

### Enclave Verifier

* `mapping(bytes32 leafHash => RSAPubKey pubKey) internal _validLeafX509s`: Mapping from leaf x509 hashes to RSA public key components


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

Allows Guardians to update their enclave keypair

*Effects*:
* The mapping `mapping(address guardian => GuardianData data) internal _guardianEnclaves` is updated for this Guardian, changing `enclaveAddress` and `enclavePubKey`

*Requirements*:
* May only be called by Guardians
* Must submit a valid ECDSA public key

---

### Enclave Verifier Functions

#### `addLeafX509`

```solidity
function addLeafX509(bytes calldata leafX509Cert) external
```

Adds a valid certificate if it is signed correctly

*Effects*:
* Adds the hashed leaf certificate as an entry to `mapping(bytes32 leafHash => RSAPubKey pubKey) internal _validLeafX509s`

*Requirements*:
* Leaf certificate must be signed by Intel's root CA

#### `removeLeafX509`

```solidity
function removeLeafX509(bytes32 hashedCert) external
```

Removes a whitelisted leaf x509 RSA public key

*Effects*:
* Removes the modulus and exponent fields from the entry within `mapping(bytes32 leafHash => RSAPubKey pubKey) internal _validLeafX509s`, indexed by the provided `hashedCert`

*Requirements*:
* May only be called by Guardians


#### `verifyEvidence`

```solidity
function verifyEvidence(
    uint256 blockNumber,
    bytes32 raveCommitment,
    RaveEvidence calldata evidence,
    bytes32 mrenclave,
    bytes32 mrsigner
) external view returns (bool)
```

Verifies remote attestation evidence. The report contains the expected MRENCLAVE/MRSIGNER values, a valid TCB status, and whether the data was signed by an Intel-issued x509 certificate. The report will contain a 64B payload in the form `(32B_Commitment || 32B_BlockHash)`, where `32B_Blockhash` is a recent L1 blockhash and `32B_Commitment` is a keccak256 hash that the enclave is committing to. The calling contract is expected to precompute `raveCommitment` from public inputs. The function returns true if the report is valid and the extracted payload matches the expected

*Effects*:
* View function; Returns true if the payload matches the expected

*Requirements*:
* Provided `blockNumber` must be within the `FRESHNESS_BLOCKS` interval
