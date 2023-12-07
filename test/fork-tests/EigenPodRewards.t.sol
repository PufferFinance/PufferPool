// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IntegrationTestHelper } from "../helpers/IntegrationTestHelper.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { PufferDeployment } from "script/DeploymentStructs.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferModuleFactory } from "puffer/PufferModuleFactory.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { PufferDeployment } from "script/DeploymentStructs.sol";
import { IEnclaveVerifier } from "puffer/interface/IEnclaveVerifier.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";

contract EigenPodsIntegrationTest is IntegrationTestHelper {
    function setUp() public {
        deployContracts();
    }

    function testNoRestakingRewardsClaiming() public {
        // 1. Create a restaking module
        vm.startPrank(0xC4a2E012024d4ff28a4E2334F58D4Cc233EB1FE1);
        pufferProtocol.createPufferModule(bytes32("EIGEN_MODULE"));
        vm.stopPrank();

        // 2. Fetch the address of the module
        address payable createdModule = payable(pufferProtocol.getModuleAddress(bytes32("EIGEN_MODULE")));

        PufferModule module = PufferModule(createdModule);

        // 3. Simulate rewards to EigenPod
        vm.deal(payable(module.getEigenPod()), 5 ether);

        // 4. Queue the withdrawal
        module.queueNonRestakingRewards();

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
