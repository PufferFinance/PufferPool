// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title EingenPodProxy
 * @author Puffer finance
 * @notice TODO: interacts with EigenLayer
 */
contract EigenPodProxy {
    /**
     * @dev Thrown if the msg.sender is unauthorized.
     */
    error Unauthorized();

    // TODO: getters, OZ ownable?
    address internal _owner;
    address internal _manager;

    constructor(address owner, address manager) {
        _owner = owner;
        _manager = manager;
    }

    modifier onlyOwner() {
        if (msg.sender != _owner) {
            revert Unauthorized();
        }
        _;
    }

    modifier onlyManager() {
        if (msg.sender != _manager) {
            revert Unauthorized();
        }
        _;
    }

    function skim() external {
        // TODO:
    }

    function eigenStake() external onlyManager {
        // TODO:
    }
}
