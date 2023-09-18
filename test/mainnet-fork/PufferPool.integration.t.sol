// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IntegrationTestHelper } from "../helpers/IntegrationTestHelper.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";

contract PufferPoolIntegrationTest is IntegrationTestHelper {
    address bob = makeAddr("bob"); // bob address is -> 0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e

    function setUp() public {
        deployContracts();
    }
}
