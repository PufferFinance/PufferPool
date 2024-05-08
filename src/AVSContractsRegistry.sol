// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";

/**
 * @title AVSContractsRegistry
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract AVSContractsRegistry is AccessManaged {
    event AvsRegistryCoordinatorSet(address indexed avsRegistryCoordinator, bool isAllowed);

    mapping(address avsRegistryCoordinator => bool allowed) internal _avsRegistryCoordinators;

    constructor(address authority) AccessManaged(authority) { }

    /**
     * @notice Sets the boolean for the AVS registry coordinator contract
     * @param avsRegistryCoordinator is the address of the registry coordinator of the AVS
     * @param isAllowed is the boolean value to set the coordinator contract is allowed or not
     */
    function setAvsRegistryCoordinator(address avsRegistryCoordinator, bool isAllowed) external restricted {
        _avsRegistryCoordinators[avsRegistryCoordinator] = isAllowed;
        emit AvsRegistryCoordinatorSet(avsRegistryCoordinator, isAllowed);
    }

    /**
     * @notice Returns `true` if the `avsRegistryCoordinator` contract is allowed
     */
    function isAllowedRegistryCoordinator(address avsRegistryCoordinator) external view returns (bool) {
        return _avsRegistryCoordinators[avsRegistryCoordinator] == true;
    }
}
