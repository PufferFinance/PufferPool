// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import {RAVE} from "rave/RAVE.sol";
import {IRave} from "rave/IRave.sol";
import {X509Verifier} from "rave/X509Verifier.sol";

interface IEnclaveVerifier {
    struct RaveEvidence {
        // Preprocessed remote attestation report
        bytes report;
        // Preprocessed RSA signature over the report
        bytes signature;
        // The hash of a whitelisted Intel-signed leaf x509 certificate
        bytes32 leafX509CertDigest;
    }

    struct RSAPubKey {
        bytes modulus;
        bytes exponent;
    }
}

contract EnclaveVerifier is IEnclaveVerifier, RAVE {
    uint256 FRESHNESS_BLOCKS;

    // RSA public key of Intel
    RSAPubKey public intelRootCAPubKey =
        RSAPubKey({
            modulus: hex"9F3C647EB5773CBB512D2732C0D7415EBB55A0FA9EDE2E649199E6821DB910D53177370977466A6A5E4786CCD2DDEBD4149D6A2F6325529DD10CC98737B0779C1A07E29C47A1AE004948476C489F45A5A15D7AC8ECC6ACC645ADB43D87679DF59C093BC5A2E9696C5478541B979E754B573914BE55D32FF4C09DDF27219934CD990527B3F92ED78FBF29246ABECB71240EF39C2D7107B447545A7FFB10EB060A68A98580219E36910952683892D6A5E2A80803193E407531404E36B315623799AA825074409754A2DFE8F5AFD5FE631E1FC2AF3808906F28A790D9DD9FE060939B125790C5805D037DF56A99531B96DE69DE33ED226CC1207D1042B5C9AB7F404FC711C0FE4769FB9578B1DC0EC469EA1A25E0FF9914886EF2699B235BB4847DD6FF40B606E6170793C2FB98B314587F9CFD257362DFEAB10B3BD2D97673A1A4BD44C453AAF47FC1F2D3D0F384F74A06F89C089F0DA6CDB7FCEEE8C9821A8E54F25C0416D18C46839A5F8012FBDD3DC74D256279ADC2C0D55AFF6F0622425D1B",
            exponent: hex"010001"
        });

    // Mapping from keccak'd leaf x509 to RSA pub key components
    mapping(bytes32 => RSAPubKey) validLeafX509s;

    // TODO add PufferPool as the owner
    constructor(uint256 _FRESHNESS_BLOCKS) {
        FRESHNESS_BLOCKS = _FRESHNESS_BLOCKS;
    }

    // Setter for intelRootCAPubKey
    function setIntelRootCAPubKey(
        bytes memory _modulus,
        bytes memory _exponent
    ) external {
        // TODO add modifier
        intelRootCAPubKey.modulus = _modulus;
        intelRootCAPubKey.exponent = _exponent;
    }

    // Getter for intelRootCAPubKey
    function getIntelRootCAPubKey() public view returns (RSAPubKey memory) {
        return intelRootCAPubKey;
    }

    // Whitelist a leaf x509 RSA public key if the x509 was signed by Intel's root CA
    function whitelistLeafX509(bytes memory leafX509Cert) external {
        // TODO add modifier
        (
            bytes memory leafCertModulus,
            bytes memory leafCertExponent
        ) = X509Verifier.verifySignedX509(
                leafX509Cert,
                intelRootCAPubKey.modulus,
                intelRootCAPubKey.exponent
            );
        bytes32 hashedCert = keccak256(leafX509Cert);

        validLeafX509s[hashedCert] = RSAPubKey({
            modulus: leafCertModulus,
            exponent: leafCertExponent
        });
    }

    // Remove a whitelisted leaf x509 RSA public key
    function removeLeafX509(bytes32 hashedCert) external {
        // TODO add modifier
        validLeafX509s[hashedCert].modulus = "";
        validLeafX509s[hashedCert].exponent = "";
    }

    // PufferPool function
    function verifyEvidence(
        bytes memory expectedPayload,
        RaveEvidence calldata evidence,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) internal view returns (bool success) {
        RSAPubKey memory leafX509 = validLeafX509s[evidence.leafX509CertDigest];
        // require(leafX509.modulus.length == todo);
        // require(leafX509.exponent == todo);

        // Recover a remote attestation payload iff everything is valid
        bytes memory recoveredPayload = verifyRemoteAttestation(
            evidence.report,
            evidence.signature,
            leafX509.modulus,
            leafX509.exponent,
            mrenclave,
            mrsigner
        );

        // Compare with the expected payload
        success = keccak256(expectedPayload) == keccak256(recoveredPayload);
    }

    function verifyGuardianPubKey(
        bytes memory pubKey,
        uint256 blockNumber,
        RaveEvidence calldata evidence,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) external view returns (bool success) {
        // Check for freshness
        require(block.number - blockNumber < FRESHNESS_BLOCKS);

        // Fetch the expected blockhash committed to by the enclave
        bytes32 gotBlockHash = blockhash(blockNumber);

        // Enclave is expected to have hashed in this order
        bytes32 digest = keccak256(abi.encode(gotBlockHash, pubKey));
        bytes memory payload = new bytes(64);

        // Pad to 64B
        assembly {
            mstore(add(payload, 32), digest)
        }

        // Getting here means the remote attestation evidence was valid
        success = verifyEvidence(payload, evidence, mrenclave, mrsigner);
    }

    function verifyValidatorPubKey(
        bytes memory pubKey,
        uint256 blockNumber,
        // TODO add the remaining fields
        RaveEvidence calldata evidence,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) external view returns (bool success) {
        // Check for freshness
        require(block.number - blockNumber < FRESHNESS_BLOCKS);

        // Fetch the expected blockhash committed to by the enclave
        bytes32 gotHash = blockhash(blockNumber);

        // Enclave is expected to have hashed in this order
        bytes32 digest = keccak256(abi.encode(gotHash, pubKey)); // TODO this needs to be updated 
        bytes memory payload = new bytes(64);

        // Pad to 64B
        assembly {
            mstore(add(payload, 32), digest)
        }

        // Getting here means the remote attestation evidence was valid
        success = verifyEvidence(payload, evidence, mrenclave, mrsigner);
    }
}
