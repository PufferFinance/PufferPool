// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";

/**
 * @title AVSContractsRegistry
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract AVSContractsRegistry is AccessManaged {
    event AvsRegistryCoordinatorSet(address indexed avsRegistryCoordinator, bytes4 selector, bool isAllowed);

    mapping(address avsRegistryCoordinator => mapping(bytes4 selector => bool allowed)) internal
        _avsRegistryCoordinators;

    constructor(address authority) AccessManaged(authority) { }

    /**
     * @notice Sets the boolean for the AVS registry coordinator contract
     * @param avsRegistryCoordinator is the address of the registry coordinator of the AVS
     * @param selector is the signature of the function
     * @param isAllowed is the boolean value to set if coordinator contract and signature are allowed or not
     */
    function setAvsRegistryCoordinator(address avsRegistryCoordinator, bytes4 selector, bool isAllowed)
        external
        restricted
    {
        _avsRegistryCoordinators[avsRegistryCoordinator][selector] = isAllowed;
        emit AvsRegistryCoordinatorSet(avsRegistryCoordinator, selector, isAllowed);
    }

    /**
     * @notice Returns `true` if the `avsRegistryCoordinator` contract is allowed
     */
    function isAllowedRegistryCoordinator(address avsRegistryCoordinator, bytes calldata customCalldata)
        external
        view
        returns (bool)
    {
        // Extract the function selector (first 4 bytes of customCalldata)
        bytes4 selector = bytes4(customCalldata[:4]);

        return _avsRegistryCoordinators[avsRegistryCoordinator][selector] == true;
    }
}
