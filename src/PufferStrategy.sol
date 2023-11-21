// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";
import { Unauthorized } from "puffer/Errors.sol";
import { Initializable } from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";
/**
 * @title PufferStartegy
 * @author Puffer Finance
 * @notice PufferStartegy
 * @custom:security-contact security@puffer.fi
 */

contract PufferStrategy is IPufferStrategy, Initializable, AccessManagedUpgradeable {
    /**
     * @dev Upgradeable contract from EigenLayer
     */

    IEigenPodManager public immutable EIGEN_POD_MANAGER;

    // keccak256(abi.encode(uint256(keccak256("PufferStrategyBase.storage")) - 1)) & ~bytes32(uint256(0xff)) @audit-info recheck this
    bytes32 private constant _PUFFER_STRATEGY_BASE_STORAGE =
        0x08d27b0961ee13de37a30c1621e160bf37a3d1fd1fd05ea89d0e3b0b7e4b2000;

    /**
     * @custom:storage-location erc7201:PufferStrategyBase.storage
     */
    struct PufferStrategyBase {
        bytes32 strategyName;
        IPufferProtocol pufferProtocol;
        IEigenPod eigenPod;
    }

    constructor(IEigenPodManager eigenPodManager) payable {
        EIGEN_POD_MANAGER = eigenPodManager;
    }

    modifier onlyPufferProtocol() {
        PufferStrategyBase storage $ = _getPufferProtocolStorage();

        if (msg.sender != address($.pufferProtocol)) {
            revert Unauthorized();
        }
        _;
    }

    function initialize(IPufferProtocol protocol, bytes32 strategyName, address initialAuthority) public initializer {
        __AccessManaged_init(initialAuthority);
        PufferStrategyBase storage $ = _getPufferProtocolStorage();
        $.pufferProtocol = protocol;
        $.strategyName = strategyName;
        $.eigenPod = IEigenPod(address(EIGEN_POD_MANAGER.ownerToPod(address(this))));
    }

    receive() external payable { }

    /**
     * @inheritdoc IPufferStrategy
     */
    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable
        onlyPufferProtocol
    {
        // EigenPod is deployed in this call
        EIGEN_POD_MANAGER.stake{ value: 32 ether }(pubKey, signature, depositDataRoot);
    }

    function collectNonRestakingRewards() external {
        // @todo limit it to 1x per day or something?
        // it creates a queued withdrawal via withdrawal router
        PufferStrategyBase storage $ = _getPufferProtocolStorage();
        $.eigenPod.withdrawBeforeRestaking();
    }

    function collectRestakingRewards() external {
        //@todo
    }

    function call(address to, uint256 amount, bytes calldata data)
        external
        restricted
        returns (bool success, bytes memory)
    {
        // slither-disable-next-line arbitrary-send-eth
        return to.call{ value: amount }(data);
    }

    /**
     * @inheritdoc IPufferStrategy
     */
    function getWithdrawalCredentials() public view returns (bytes memory) {
        // Withdrawal credentials for EIgenLayer strategies are EigenPods
        PufferStrategyBase storage $ = _getPufferProtocolStorage();
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), $.eigenPod);
    }

    /**
     * @inheritdoc IPufferStrategy
     */
    function NAME() external view returns (bytes32) {
        PufferStrategyBase storage $ = _getPufferProtocolStorage();
        return $.strategyName;
    }

    function _getPufferProtocolStorage() internal pure returns (PufferStrategyBase storage $) {
        // solhint-disable-next-line
        assembly {
            $.slot := _PUFFER_STRATEGY_BASE_STORAGE
        }
    }
}
