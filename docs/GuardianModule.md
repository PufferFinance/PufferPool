# GuardianModule

Guardians play a crucial role in our system and are a collective of respected community members who are deeply aligned with Ethereum's principles and values.

Our guardians have their own EOAs (Externally Owned Accounts) that are stored in the [GuardianModule](../src/GuardianModule.sol), and at the same time, they are running [enclaves](https://en.wikipedia.org/wiki/Trusted_execution_environment) and creating a wallet (EOA) inside of an enclave. The wallets from the enclave are used to sign data that the enclave produces. 

GuardianModule is used to ensure that the guardians are:
- Using a trusted execution environment
- Signing a valid data with the corresponding wallet enclave/EOA

The Guardian module allows guardians to change their enclave address to a new enclave address by calling `rotateGuardianKey`. For this purpose, we are using [EnclaveVerifier](./EnclaveVerifier.md). It ensures that the guardians are using enclaves.

The roles of the guardians are:
- Provisioning new validators
- Skipping the provisioning of new validators
- Ejecting validators
- Validator tickets accounting for node operators
- Handling of the full withdrawals
- Reporting of the number of active Puffer/all active Ethereum validators

For some parts of our system, guardians can use a their EOAs to a craft signatures and interact with the Puffer smart contracts, while for others, we require signatures coming from the guardians' enclave wallets.

Guardian module is receiving and holding funds that are used to subsidize the operating costs (infrastructure, gas).

The DAO can set [enclave measurements(MRENCLAVE, MRSIGNER)](https://www.intel.com/content/www/us/en/developer/articles/technical/introduction-to-intel-sgx-sealing.html), add/remove guardians using the restricted functions.

### Important variables

- `_guardians` is the list of unique addresses of the guardians.
- `_threshold` represents the minimum number of guardians that are required to sign off on some operation in the system. It is very similar to threshold of a standard multi-sig wallet. 
- `_mrsigner` is the measurement of the enclave signer.
- `_mrenclave` is the measurement of the enclave.
- `_ejectionThreshold` is the ETH balance threshold that triggers the ejection of a validator. If it falls below this threshold, the guardians will eject the validator.
- `_guardianEnclaves` is a mapping of guardian addresses to their enclave addresses.

### Functions

#### rotateGuardianKey
A guardian can call this function at any time to change the enclave signing wallet. The key rotation will only be valid if the guardian is using a fresh RAVE(remote attestation verification) evidence in the transaction. Each guardian will have to call this at least once for initial setup.

#### _validateSignatures (internal function used by the external functions)
Is the most important function in the contract. It checks weather the data was signed by the guardians. The ordering of signatures that are submitted to PufferProtocol <strong>MUST</strong> be the same as the one returned from `function getGuardians() returns (address[] memory)` for EOA wallets, and `function getGuardiansEnclaveAddresses() returns(address[] memory)` for enclave wallets.