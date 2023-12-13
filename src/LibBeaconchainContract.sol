// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title LibBeaconchainContract
 * @dev Copied from the deposit contract
 *         https://github.com/ethereum/consensus-specs/blob/dev/solidity_deposit_contract/deposit_contract.sol
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
library LibBeaconchainContract {
    /**
     * @notice Returns the deposit data root
     * @param pubKey is the public key
     * @param signature is the signature
     * @param withdrawalCredentials is the withdrawal credentials
     * @return the deposit data root
     */
    function getDepositDataRoot(bytes calldata pubKey, bytes calldata signature, bytes calldata withdrawalCredentials)
        external
        pure
        returns (bytes32)
    {
        bytes32 pubKeyRoot = sha256(abi.encodePacked(pubKey, bytes16(0)));
        bytes32 signatureRoot = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(signature[:64])), sha256(abi.encodePacked(signature[64:], bytes32(0)))
            )
        );
        return sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(pubKeyRoot, withdrawalCredentials)),
                sha256(abi.encodePacked(_toLittleEndian64(uint64(32 ether / 1 gwei)), bytes24(0), signatureRoot))
            )
        );
    }

    function _toLittleEndian64(uint64 value) private pure returns (bytes memory ret) {
        // Copied https://github.com/ethereum/consensus-specs/blob/b04430332ec190774f4dfc039de6e83afe3327ee/solidity_deposit_contract/deposit_contract.sol#L165
        ret = new bytes(8);
        bytes8 bytesValue = bytes8(value);
        // Byteswapping during copying to bytes.
        ret[0] = bytesValue[7];
        ret[1] = bytesValue[6];
        ret[2] = bytesValue[5];
        ret[3] = bytesValue[4];
        ret[4] = bytesValue[3];
        ret[5] = bytesValue[2];
        ret[6] = bytesValue[1];
        ret[7] = bytesValue[0];
    }
}
