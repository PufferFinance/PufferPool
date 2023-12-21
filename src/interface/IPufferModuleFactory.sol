// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferModule } from "puffer/interface/IPufferModule.sol";

interface IPufferModuleFactory {
    /**
     * @notice Thrown if the Creation of new module failed
     * @dev Signature "0x04a5b3ee"
     */
    error Create2Failed();

    /**
     * @notice Create a new Puffer module
     * @dev This function creates a new Puffer module with the given module name
     * @param moduleName The name of the module
     * @param metadataURI is a URI for the operator's metadata, i.e. a link providing more details on the operator.
     *
     * @param delegationApprover Address to verify signatures when a staker wishes to delegate to the operator, as well as controlling "forced undelegations".
     * @dev Signature verification follows these rules:
     * 1) If this address is left as address(0), then any staker will be free to delegate to the operator, i.e. no signature verification will be performed.
     * 2) If this address is an EOA (i.e. it has no code), then we follow standard ECDSA signature verification for delegations to the operator.
     * 3) If this address is a contract (i.e. it has code) then we forward a call to the contract and verify that it returns the correct EIP-1271 "magic value".
     * @return module The newly created Puffer module
     */
    function createNewPufferModule(bytes32 moduleName, string calldata metadataURI, address delegationApprover)
        external
        returns (IPufferModule module);
}
