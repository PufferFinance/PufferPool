// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

interface RAVeInterface {
	function rave(
        bytes memory _report,
        bytes memory _sig,
        bytes memory _leafX509Cert,
        bytes memory _signingMod,
        bytes memory _signingExp,
        bytes32 _mrenclave,
        bytes32 _mrsigner
    ) external view returns (bytes memory _payload);

    // Assumes _signingMod and _signingExp are whitelisted
    function verifyRemoteAttestation(
        bytes memory _report,
        bytes memory _sig,
        bytes memory _signingMod,
        bytes memory ,
        bytes32 _mrenclave,
        bytes32 _mrsigner
    ) external view returns (bytes memory _payload);

    // Used to whitelist an x509's modulus and exponent for amortizing gas costs
    function verifySignedX509(bytes memory cert, bytes memory parentMod, bytes memory parentExp)
        external
        view
        returns (bytes memory rsaModulus, bytes memory rsaExponent);
}