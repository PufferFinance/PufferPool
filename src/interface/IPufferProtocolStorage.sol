// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPoolStorage } from "puffer/struct/PufferPoolStorage.sol";

interface IPufferProtocolStorage {
    /**
     * @notice Returns the PufferPool storage
     */
    function getPuferPoolStorage() external pure returns (PufferPoolStorage memory);
}
