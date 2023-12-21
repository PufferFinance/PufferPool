// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { IPufferModuleFactory } from "puffer/interface/IPufferModuleFactory.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { Create2 } from "openzeppelin/utils/Create2.sol";

/**
 * @title PufferModuleFactory
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferModuleFactory is IPufferModuleFactory {
    /**
     * @notice Address of the PufferModule proxy beacon
     */
    address public immutable PUFFER_MODULE_BEACON;

    /**
     * @notice Address of the authority
     */
    address public immutable AUTHORITY;

    /**
     * @notice Address of the Puffer Protocol
     */
    address public immutable PUFFER_PROTOCOL;

    constructor(address beacon, address pufferProtocol, address authority) {
        PUFFER_MODULE_BEACON = beacon;
        AUTHORITY = authority;
        PUFFER_PROTOCOL = pufferProtocol;
    }

    /**
     * @inheritdoc IPufferModuleFactory
     */
    function createNewPufferModule(bytes32 moduleName, string memory metadataURI, address delegationApprover)
        external
        returns (IPufferModule module)
    {
        module = IPufferModule(
            Create2.deploy({
                amount: 0,
                salt: moduleName,
                bytecode: abi.encodePacked(
                    type(BeaconProxy).creationCode,
                    abi.encode(
                        PUFFER_MODULE_BEACON,
                        abi.encodeCall(PufferModule.initialize, (moduleName, AUTHORITY, metadataURI, delegationApprover))
                    )
                    )
            })
        );
    }
}
