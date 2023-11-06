// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferProtocolStorage } from "puffer/interface/IPufferProtocolStorage.sol";
import { ProtocolStorage } from "puffer/struct/ProtocolStorage.sol";
import { PufferPoolStorage } from "puffer/struct/PufferPoolStorage.sol";

/**
 * @title PufferProtocolStorage
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
abstract contract PufferProtocolStorage is IPufferProtocolStorage {
    /**
     * @dev Constant representing 100%
     */
    uint256 internal constant _ONE_HUNDRED_WAD = 100 * 1e18; // 1e18 = WAD

    uint256 public constant BURST_THRESHOLD = 20;

    /**
     * @dev Storage slot location for PufferProtocol
     * @custom:storage-location erc7201:PufferProtocol.storage
     */
    bytes32 private constant _PUFFER_PROTOCOL_STORAGE =
        0xb8d3716136db480afe9a80da6be84f994509ecf9515ed14d03024589b5f2bd00;

    /**
     * @dev Storage slot location for PufferPool
     * @custom:storage-location erc7201:PufferPool.storage
     */
    bytes32 private constant _PUFFER_POOL_STORAGE = 0x3d9197675aec7b7f62441149aba7986872b7337d003616efa547249bb6c43900;

    function getPuferPoolStorage() external pure returns (PufferPoolStorage memory) {
        PufferPoolStorage storage $;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := _PUFFER_POOL_STORAGE
        }

        return $;
    }

    function _getPuferPoolStorage() internal pure returns (PufferPoolStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := _PUFFER_POOL_STORAGE
        }
    }

    function _getPufferProtocolStorage() internal pure returns (ProtocolStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := _PUFFER_PROTOCOL_STORAGE
        }
    }
}
