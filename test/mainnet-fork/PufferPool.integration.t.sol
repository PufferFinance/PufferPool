// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IntegrationTestHelper } from "../helpers/IntegrationTestHelper.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import "forge-std/console.sol";

contract PufferPoolIntegrationTest is IntegrationTestHelper {
    function setUp() public {
        deployContracts();
    }

    function testgetEigenPodProxy() public {
        // Sanity check
        address bob = makeAddr("bob"); // bob address is -> 0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e
        vm.startPrank(bob);
        console.log(bob, "bob addr");
        address bobPod = address(IEigenPodManager(pool.EIGEN_POD_MANAGER()).getPod(bob));
        // bob pod should be 0x0a71F48B3052008eFE486a9EeBF3ab44a62B7703
        // verify on etherscan https://etherscan.io/address/0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338#readProxyContract .getPod(bob)
        assertEq(bobPod, 0x0a71F48B3052008eFE486a9EeBF3ab44a62B7703, "bad bob pod");

        (address eigenPodProxy, address eigenPod) = pool.getEigenPodProxyAndEigenPod(bytes("asd"));
        vm.stopPrank();

        // Both addresses can be hardcoded
        assertEq(eigenPodProxy, 0x9Deeab39DEA8Aef7Dab8D0A1520349A6381023F9, "eigen pod proxy address");
        assertEq(eigenPod, 0xF4A7A13aa80f402F91ac368a3a3BeafFBb6Ee7fe, "eigen pod proxy address");
    }
}
