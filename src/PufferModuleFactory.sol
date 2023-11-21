// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { IPufferModuleFactory } from "puffer/interface/IPufferModuleFactory.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";

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
    function createNewPufferModule(bytes32 moduleName) external returns (IPufferModule module) {
        bytes memory deploymentData = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(
                PUFFER_MODULE_BEACON,
                abi.encodeWithSignature("initialize(address,bytes32,address)", msg.sender, moduleName, AUTHORITY)
            )
        );

        // solhint-disable-next-line no-inline-assembly
        assembly {
            module := create2(0x0, add(0x20, deploymentData), mload(deploymentData), moduleName)
        }

        if (address(module) == address(0)) {
            revert Create2Failed();
        }

        return IPufferModule(payable(address(module)));
    }
}
