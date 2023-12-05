# Guardians

| File | Type | Upgradeable | Inherited | Deployed |
| -------- | -------- | -------- | -------- | -------- |
| [`IGuardianModule.sol`](../src/interface/IGuardianModule.sol) | Singleton | / | YES | / |
| [`IEnclaveVerifier.sol`](../src/interface/IEnclaveVerifier.sol) | Singleton | / | YES |/ |
| [`EnclaveVerifier.sol`](../src/EnclaveVerifier.sol) | Singleton | NO | YES | / |
| [`GuardianModule.sol`](../src/GuardianModule.sol) | Singleton | NO | NO | / |

Guardians play a crucial role in our system and are a collective of respected community members who are deeply aligned with Ethereum's principles and values.

We are deploying and enabling [GuardianModule.sol](../src/GuardianModule.sol) and creating a wallet inside of an enclave. The wallets from the enclave are used to sign data that the enclave produces. GuardianModule is used to ensure that the Guardians are:
- Running the correct version of an Intel SGX enclave
- Verifying signatures from the Guardians enclaves and EOAs to perform their duties

Guardians are running enclaves that have very limited functionality. Particularly, the enclave has only three functionalities:

1. Create a fresh ETH keypair and attest to its creation via remote attestation evidence. The private key is kept private even to the Guardian

2. Sign off on a NoOp's beacon chain deposit message if it was valid and the enclave was able to receive custody of an encrypted keyshare and verify remote attestation evidence

3. Produce a partial signature for a `VoluntaryExit` Message. If a threshold of Guardians combine these signatures they are able to withdraw a validator should their balance fall too low or their smoothing commitment duration expire.

The GuardianModule allows Guardians to rotate their enclave ETH keypairs using [EnclaveVerifier](./EnclaveVerifier.md). It ensures that the Guardians are using the correct enclave version by verifying remote attestation evidence.

The roles of the Guardians are:
- Provisioning ETH to Validators
- Calculating and Posting Proof of Rewards (the amount of ETH backing pufETH)
- Ejecting validators
- Skipping provisioning ETH to validators with invalid deposit messages

#### Future of Guardians

Since Puffer's goal is full protocol-level decentralization, we plan to eventually remove the need for Guardians (and any other trusted entities) as two particular EIPs are released: EIP-7002 and EIP-4788:

* EIP-7002: Once implemented, it will render the Guardian's role in overseeing validator ejections obsolete as they can be triggered from a smart contract.
* EIP-4788: Allows for trustless proof of reserves, removing the dependency on any trusted entity to report how much ETH is backing pufETH.

Until these EIPs are fully adopted, the Guardians serve as an interim measure. They allow the Puffer Protocol to grow and decentralize Ethereum safely, ensuring pooled stakers remain shielded from risks and uncertainties in the interim. The Guardians' role, although crucial now, is a temporary measure designed to safeguard staker assets and ensure protocol growth in Ethereum's constantly evolving landscape.

#### High-level Concepts

This document organizes methods according to the following themes (click each to be taken to the relevant section):
* [Guardian Functions](#guardian-functions)
* [Enclave Verifier Functions](#enclave-verifier-functions)

#### Important state variables

### Guardian Module

* `EnumerableSet.AddressSet private _guardians`: The set of Guardian EOA addresses
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
