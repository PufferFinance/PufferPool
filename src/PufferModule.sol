// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { Unauthorized } from "puffer/Errors.sol";
import { Initializable } from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";
/**
 * @title PufferStartegy
 * @author Puffer Finance
 * @notice PufferStartegy
 * @custom:security-contact security@puffer.fi
 */

contract PufferModule is IPufferModule, Initializable, AccessManagedUpgradeable {
    /**
     * @dev Upgradeable contract from EigenLayer
     */

    IEigenPodManager public immutable EIGEN_POD_MANAGER;

    // keccak256(abi.encode(uint256(keccak256("PufferModuleBase.storage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _PUFFER_MODULE_BASE_STORAGE =
        0xd1bf6fe7a57849dfa0cdbc909a9468d68de91a273148664d5309c08b532a8400;

    /**
     * @custom:storage-location erc7201:PufferModuleBase.storage
     */
    struct PufferModuleBase {
        bytes32 moduleName;
        IPufferProtocol pufferProtocol;
        IEigenPod eigenPod;
    }

    constructor(IEigenPodManager eigenPodManager) payable {
        EIGEN_POD_MANAGER = eigenPodManager;
    }

    modifier onlyPufferProtocol() {
        PufferModuleBase storage $ = _getPufferProtocolStorage();

        if (msg.sender != address($.pufferProtocol)) {
            revert Unauthorized();
        }
        _;
    }

    function initialize(IPufferProtocol protocol, bytes32 moduleName, address initialAuthority) public initializer {
        __AccessManaged_init(initialAuthority);
        PufferModuleBase storage $ = _getPufferProtocolStorage();
        $.pufferProtocol = protocol;
        $.moduleName = moduleName;
        $.eigenPod = IEigenPod(address(EIGEN_POD_MANAGER.ownerToPod(address(this))));
    }

    receive() external payable { }

    /**
     * @inheritdoc IPufferModule
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
        PufferModuleBase storage $ = _getPufferProtocolStorage();
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
     * @inheritdoc IPufferModule
     */
    function getWithdrawalCredentials() public view returns (bytes memory) {
        // Withdrawal credentials for EigenLayer modules are EigenPods
        PufferModuleBase storage $ = _getPufferProtocolStorage();
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), $.eigenPod);
    }

    /**
     * @inheritdoc IPufferModule
     */
    function NAME() external view returns (bytes32) {
        PufferModuleBase storage $ = _getPufferProtocolStorage();
        return $.moduleName;
    }

    function _getPufferProtocolStorage() internal pure returns (PufferModuleBase storage $) {
        // solhint-disable-next-line
        assembly {
            $.slot := _PUFFER_MODULE_BASE_STORAGE
        }
    }
}
