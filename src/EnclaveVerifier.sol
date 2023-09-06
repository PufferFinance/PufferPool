// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { RAVE } from "rave/RAVE.sol";
import { X509Verifier } from "rave/X509Verifier.sol";
import { IEnclaveVerifier } from "puffer/interface/IEnclaveVerifier.sol";
import { RaveEvidence } from "puffer/interface/RaveEvidence.sol";
import { console2 } from "forge-std/console2.sol";
import { StdStyle } from "forge-std/StdStyle.sol";

/**
 * @title EnclaveVerifier
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
contract EnclaveVerifier is IEnclaveVerifier, RAVE {
    /**
     * @dev RSA Public key for Intel: https://api.portal.trustedservices.intel.com/documentation
     */
    bytes internal constant _INTEL_RSA_MODULUS =
        hex"9F3C647EB5773CBB512D2732C0D7415EBB55A0FA9EDE2E649199E6821DB910D53177370977466A6A5E4786CCD2DDEBD4149D6A2F6325529DD10CC98737B0779C1A07E29C47A1AE004948476C489F45A5A15D7AC8ECC6ACC645ADB43D87679DF59C093BC5A2E9696C5478541B979E754B573914BE55D32FF4C09DDF27219934CD990527B3F92ED78FBF29246ABECB71240EF39C2D7107B447545A7FFB10EB060A68A98580219E36910952683892D6A5E2A80803193E407531404E36B315623799AA825074409754A2DFE8F5AFD5FE631E1FC2AF3808906F28A790D9DD9FE060939B125790C5805D037DF56A99531B96DE69DE33ED226CC1207D1042B5C9AB7F404FC711C0FE4769FB9578B1DC0EC469EA1A25E0FF9914886EF2699B235BB4847DD6FF40B606E6170793C2FB98B314587F9CFD257362DFEAB10B3BD2D97673A1A4BD44C453AAF47FC1F2D3D0F384F74A06F89C089F0DA6CDB7FCEEE8C9821A8E54F25C0416D18C46839A5F8012FBDD3DC74D256279ADC2C0D55AFF6F0622425D1B";
    bytes internal constant _INTEL_EXPONENT = hex"010001";

    /**
     * @notice Freshness number of blocks
     */
    uint256 public immutable FRESHNESS_BLOCKS;

    /**
     * @notice PufferPool
     */
    address public immutable POOL;

    /**
     * @dev Mapping from keccak'd leaf x509 to RSA pub key components
     * leafHash -> pubKey
     */
    mapping(bytes32 => RSAPubKey) internal _validLeafX509s;

    modifier onlyPool() {
        if (msg.sender != POOL) {
            revert Unauthorized();
        }
        _;
    }

    constructor(uint256 freshnessBlocks, address pufferPool) {
        FRESHNESS_BLOCKS = freshnessBlocks;
        POOL = pufferPool;
    }

    /**
     * @inheritdoc IEnclaveVerifier
     */
    function getIntelRootCAPubKey() public pure returns (RSAPubKey memory) {
        return RSAPubKey({ modulus: _INTEL_RSA_MODULUS, exponent: _INTEL_EXPONENT });
    }

    /**
     * @notice Adds a leaf x509 RSA public key if the x509 was signed by Intel's root CA
     */
    function addLeafX509(bytes calldata leafX509Cert) external {
        (bytes memory leafCertModulus, bytes memory leafCertExponent) =
            X509Verifier.verifySignedX509(leafX509Cert, _INTEL_RSA_MODULUS, _INTEL_EXPONENT);

        bytes32 hashedCert = keccak256(leafX509Cert);

        _validLeafX509s[hashedCert] = RSAPubKey({ modulus: leafCertModulus, exponent: leafCertExponent });

        emit AddedPubKey(hashedCert);
    }

    /**
     * @notice Removes a whitelisted leaf x509 RSA public key
     */
    function removeLeafX509(bytes32 hashedCert) external onlyPool {
        delete _validLeafX509s[hashedCert].modulus;
        delete _validLeafX509s[hashedCert].exponent;

        emit RemovedPubKey(hashedCert);
    }

    /**
     * @inheritdoc IEnclaveVerifier
     */
    function verifyEvidence(
        uint256 blockNumber,
        bytes32 raveCommitment,
        RaveEvidence calldata evidence,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) external view returns (bool) {
        // Check for freshness
        if ((block.number - blockNumber) > FRESHNESS_BLOCKS) {
            revert StaleEvidence();
        }

        RSAPubKey memory leafX509 = _validLeafX509s[evidence.leafX509CertDigest];

        console2.log(StdStyle.magenta("IF YOU CAN SEE THE NEXT console.log, YOU DID IT :D (hopefully)"));

        // Recover a remote attestation payload if everything is valid
        bytes memory recoveredPayload = verifyRemoteAttestation(
            evidence.report, evidence.signature, leafX509.modulus, leafX509.exponent, mrenclave, mrsigner
        );

        console2.log(StdStyle.magenta("======== YOU DID IT! now we need to make sure that tha payloads match ======== "));

        // Remote attestation payloads are expected to be in the form (32B_Commitment || 32B_BlockHash)
        bytes memory expectedPayload = abi.encode(raveCommitment, blockhash(blockNumber));

        console2.log("Expected");
        console2.logBytes(expectedPayload);

        console2.log("Recovered");
        console2.logBytes(recoveredPayload);

        // Compare with the expected payload
        return (keccak256(expectedPayload) == keccak256(recoveredPayload));
    }
}
