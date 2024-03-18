// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IntegrationTestHelper } from "../helpers/IntegrationTestHelper.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";

contract EigenPodRewards is IntegrationTestHelper {
    function setUp() public {
        deployContracts();
    }

    //@todo fix with new holesky testnet
    function test_noRestakingRewardsClaiming() public {
        // 1. Create a restaking module
        vm.startPrank(0xC4a2E012024d4ff28a4E2334F58D4Cc233EB1FE1);
        pufferProtocol.createPufferModule(bytes32("EIGEN_DA"));
        vm.stopPrank();

        // 2. Fetch the address of the module
        address payable createdModule = payable(pufferProtocol.getModuleAddress(bytes32("EIGEN_DA")));

        bytes memory pubKey = bytes.concat(abi.encodePacked(bytes32("mockPubKey")), bytes16(""));
        bytes memory signatureMock =
            hex"8aa088146c8c6ca6d8ad96648f20e791be7c449ce7035a6bd0a136b8c7b7867f730428af8d4a2b69658bfdade185d6110b938d7a59e98d905e922d53432e216dc88c3384157d74200d3f2de51d31737ce19098ff4d4f54f77f0175e23ac98da5";

        PufferModule module = PufferModule(createdModule);

        bytes32 depositDataRoot = getDepositData(pubKey, signatureMock, module.getWithdrawalCredentials());
        // Simulate callStake
        vm.startPrank(address(pufferProtocol));
        vm.deal(payable(module), 32 ether);
        module.callStake({ pubKey: pubKey, signature: signatureMock, depositDataRoot: depositDataRoot });
        vm.stopPrank();

        // 3. Simulate rewards to EigenPod
        vm.deal(payable(module.getEigenPod()), 5 ether);

        // 4. Queue the withdrawal
        vm.startPrank(address(pufferProtocol.PUFFER_MODULE_MANAGER())); //@todo hacky, make it proper
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
