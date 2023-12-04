# EnclaveVerifier

 EnclaveVerifier is a smart contract for verifying Intel SGX remote attestation reports signed by [Intel's Attestation Service, adhering to the EPID specs](https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf). SGX devices can use these contracts to prove on-chain that they are running the expected enclave and have committed to some data.

At a high level, EnclaveVerifier verifies that the leaf x509 certificate used to sign the attestation report originates from Intel. The report is parsed, its enclave measurements are verified, and finally the 64 byte enclave committed data (a public key) is extracted. 

In the context of the PufferProtocol, the EnclaveVerifier is used to register Guardian enclaves. It is used in the function `rotateGuardianKey()` within the [Guardian Module](../src/GuardianModule.sol) to verify the submitted RaveEvidence. The Guardians must commit to a blockhash which is checked during verification of this evidence to ensure the block is recent, and thus that the key is fresh. The EnclaveVerifier must also have the same enclave measurements (MRENCLAVE and MRSIGNER values) that the protocol's DAO registers.