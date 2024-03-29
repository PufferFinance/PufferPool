# GuardianModule

The GuardianModule is a contract that is used to manage the guardians of the Puffer system. 
GuardianModule is used to ensure that the guardians are:
- Using a trusted execution environment (TEE)
- Signing valid data with the corresponding wallet enclave/EOA

The Guardian module allows guardians to change their enclave address to a new enclave address by calling `rotateGuardianKey`. For this purpose, we are using [EnclaveVerifier](./EnclaveVerifier.md) to ensures that the guardians are using enclaves correctly.


## Guardians 

Guardians play a crucial role in Puffer system and are a collective of respected community members who are deeply aligned with Ethereum's principles and values.

Puffer guardians have their own EOAs (Externally Owned Accounts) that are assigned in the [GuardianModule](../src/GuardianModule.sol). Additionally, they are running [enclaves](https://en.wikipedia.org/wiki/Trusted_execution_environment) and creating a wallet (EOA) inside the enclave. The wallets inside the enclave are used to sign enclave's output data. 


The roles of the guardians are:
- Provisioning new validators
- Skipping the provisioning of new validators if needed
- Ejecting validators
- Validator tickets accounting for node operators
- Handling of the full withdrawals requests
- Reporting of the number of active Puffer and all active Ethereum validators

For some parts of our system, guardians can use their EOAs to craft signatures and interact with the Puffer smart contracts, while for others, we require signatures coming from the guardians' enclave wallets.

Guardian module is receiving and holding funds that are used to subsidize the operating costs (infrastructure, gas).

The DAO can set [enclave measurements(MRENCLAVE, MRSIGNER)](https://www.intel.com/content/www/us/en/developer/articles/technical/introduction-to-intel-sgx-sealing.html), add/remove guardians using the restricted functions.

## Important variables

- `_guardians` is the list of unique addresses of the guardians.
- `_threshold` represents the minimum number of guardians that are required to sign off on some operation in the system. It is very similar to threshold of a standard multi-sig wallet. 
- `_mrsigner` is the measurement of the enclave signer.
- `_mrenclave` is the measurement of the enclave.
- `_ejectionThreshold` is the ETH balance threshold that triggers the ejection of a validator. If the validator's balance falls below this threshold, the guardians will eject the validator.
- `_guardianEnclaves` is a mapping of guardian addresses to their enclave addresses.

## Functions

### rotateGuardianKey
A guardian can call this function at any time to change the enclave signing wallet. The key rotation will only be valid if the guardian is using a fresh RAVE(Remote Attestation Verification Evidence) in the transaction. Each guardian will have to call this at least once for initial setup.

### _validateSignatures (internal function used by the external functions)
Is the most important function in the contract. It checks whether the data was signed by the guardians or is invalid. The ordering of signatures that are submitted to PufferProtocol <strong>MUST</strong> be the same as the one returned from `function getGuardians() returns (address[] memory)` for EOA wallets, and `function getGuardiansEnclaveAddresses() returns(address[] memory)` for enclave wallets.