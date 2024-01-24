// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IntegrationTestHelper } from "../helpers/IntegrationTestHelper.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { PufferProtocolDeployment } from "script/DeploymentStructs.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";

contract EigenPodRewards is IntegrationTestHelper {
    function setUp() public {
        deployContracts();
    }

    function testNoRestakingRewardsClaiming() public {
        // 1. Create a restaking module
        vm.startPrank(0xC4a2E012024d4ff28a4E2334F58D4Cc233EB1FE1);
        pufferProtocol.createPufferModule(bytes32("EIGEN_DA"), "", address(0));
        vm.stopPrank();

        // 2. Fetch the address of the module
        address payable createdModule = payable(pufferProtocol.getModuleAddress(bytes32("EIGEN_DA")));

        PufferModule module = PufferModule(createdModule);

        // 3. Simulate rewards to EigenPod
        vm.deal(payable(module.getEigenPod()), 5 ether);

        // 4. Queue the withdrawal
        module.queueNonRestakingRewards();

        // Try claiming right away, it doesn't revert, but the amount claimed is 0
        module.claimNonRestakingRewards();

        // 5. Fast forward 10 days into the future
        vm.roll(18_794_775);

        // Assert that we had 0 before claiming
        assertEq(0, createdModule.balance, "zero balance before");

        // 6. Claim
        module.claimNonRestakingRewards();

        // Assert that we got ETH from our router
        assertEq(5 ether, createdModule.balance, "5 ether balance after claiming");
    }
}
