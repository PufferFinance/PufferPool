// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { Initializable } from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title PufferStartegy
 * @author Puffer Finance
 * @notice PufferStartegy TODO:
 * @custom:security-contact security@puffer.fi
 */
contract PufferStrategy is Initializable, AccessManagedUpgradeable {
    /**
     * @dev Upgradeable contract from EigenLayer
     */
    IEigenPodManager internal immutable EIGEN_POD_MANAGER;

    // keccak256(abi.encode(uint256(keccak256("PufferStrategyBase.storage")) - 1)) & ~bytes32(uint256(0xff)) @audit-info recheck this
    bytes32 private constant PUFFER_STRATEGY_BASE_STORAGE =
        0x08d27b0961ee13de37a30c1621e160bf37a3d1fd1fd05ea89d0e3b0b7e4b2000;

    /**
     * @custom:storage-location erc7201:PufferStrategyBase.storage
     */
    struct PufferStrategyBase {
        PufferProtocol pufferProtocol;
        IEigenPod eigenPod;
    }

    constructor(IEigenPodManager eigenPodManager) {
        EIGEN_POD_MANAGER = eigenPodManager;
    }

    function initialize(PufferProtocol protocol) public initializer {
        PufferStrategyBase storage $ = _getPufferProtocolStorage();
        $.pufferProtocol = protocol;
        $.eigenPod = IEigenPod(address(EIGEN_POD_MANAGER.ownerToPod(address(this))));
    }

    receive() external payable { }

    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable
        restricted
    {
        // EigenPod is deployed in this call
        EIGEN_POD_MANAGER.stake{ value: 32 ether }(pubKey, signature, depositDataRoot);
    }

    function collectRewardsIfNotRestaking() external {
        // @todo limit it to 1x per day or something?
        // it creates a queued withdrawal via withdrawal router
        PufferStrategyBase storage $ = _getPufferProtocolStorage();
        $.eigenPod.withdrawBeforeRestaking();
    }

    function getEigenPod() external view returns (address) {
        PufferStrategyBase storage $ = _getPufferProtocolStorage();
        return address($.eigenPod);
    }

    // TODO: the restaking

    function _getPufferProtocolStorage() internal pure returns (PufferStrategyBase storage $) {
        assembly {
            $.slot := PUFFER_STRATEGY_BASE_STORAGE
        }
    }
}
