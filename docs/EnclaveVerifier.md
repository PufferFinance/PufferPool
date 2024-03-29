# EnclaveVerifier

 *EnclaveVerifier* is a smart contract for verifying Intel SGX remote attestation reports signed by [Intel's Attestation Service, adhering to the EPID specs](https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf). SGX devices can use these contracts to prove on-chain that they are running the expected enclave (attestation) and have committed to some data.

At a high level *EnclaveVerifier* verifies that the leaf x509 certificate used to sign the attestation report originates from Intel. The report is parsed, its enclave measurements are verified, and finally the 64 byte enclave committed data (a public key) is extracted. 