// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { PufferStrategy } from "puffer/PufferStrategy.sol";
import { NoRestakingStrategy } from "puffer/NoRestakingStrategy.sol";
import { Script } from "forge-std/Script.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { ERC1967Proxy } from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { GuardianModule } from "../src/GuardianModule.sol";
import { EigenPodManagerMock } from "../test/mocks/EigenPodManagerMock.sol";
import { console } from "forge-std/console.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { Strings } from "openzeppelin/utils/Strings.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";

/**
 * @title DeployPuffer
 * @author Puffer finance
 * @notice Deploys PufferPool Contracts
 * @dev
 *
 *
 *         NOTE:
 *
 *         If you ran the deployment script, but did not `--broadcast` the transaction, it will still update your local chainId-deployment.json file.
 *         Other scripts will fail because addresses will be updated in deployments file, but the deployment never happened.
 *
 *
 *         forge script script/DeployPuffer.s.sol:DeployPuffer -vvvv --rpc-url=$EPHEMERY_RPC_URL --broadcast
 */
contract DeployPuffer is BaseScript {
    function run() public broadcast returns (PufferProtocol, PufferPool, AccessManager) {
        string memory guardiansDeployment =
            vm.readFile(string.concat("./output/", Strings.toString(block.chainid), "-guardians.json"));
        string memory obj = "";

        PufferProtocol pufferProtocolImpl;

        AccessManager accessManager = AccessManager(stdJson.readAddress(guardiansDeployment, ".accessManager"));

        {
            // PufferTreasury
            address payable treasury = payable(vm.envOr("TREASURY", address(1337)));
            address payable guardians = payable(stdJson.readAddress(guardiansDeployment, ".guardians"));

            address eigenStrategyManager = vm.envOr("EIGEN_STRATEGY_MANAGER", address(0));
            address eigenSlasher = vm.envOr("EIGEN_SLASHER", address(0));

            address eigenPodManager = vm.envOr("EIGENPOD_MANAGER", address(new EigenPodManagerMock()));

            PufferStrategy strategyImplementation = new PufferStrategy(IEigenPodManager(eigenPodManager));

            UpgradeableBeacon beacon = new UpgradeableBeacon(address(strategyImplementation), address(accessManager));
            vm.serializeAddress(obj, "PufferStrategyBeacon", address(beacon));

            // Puffer Service implementation
            pufferProtocolImpl =
                new PufferProtocol({guardians: Safe(guardians), treasury: treasury, strategyBeacon: address(beacon)});
        }

        // UUPS proxy for PufferProtocol
        ERC1967Proxy proxy = new ERC1967Proxy(address(pufferProtocolImpl), "");

        PufferProtocol pufferProtocol = PufferProtocol(payable(address(proxy)));
        // Deploy pool
        PufferPool pool = new PufferPool(pufferProtocol, address(accessManager));

        WithdrawalPool withdrawalPool = new WithdrawalPool(pool);

        // Read guardians module variable
        address payable guardiansModule = payable(stdJson.readAddress(guardiansDeployment, ".guardianModule"));

        NoRestakingStrategy noRestaking = new NoRestakingStrategy(address(accessManager), pufferProtocol);

        // Initialize the Pool
        pufferProtocol.initialize({
            accessManager: address(accessManager),
            pool: pool,
            withdrawalPool: withdrawalPool,
            guardianSafeModule: guardiansModule,
            noRestakingStrategy: address(noRestaking)
        });

        vm.serializeAddress(obj, "PufferProtocolImplementation", address(pufferProtocolImpl));
        vm.serializeAddress(obj, "noRestakingStrategy", address(noRestaking));
        vm.serializeAddress(obj, "pufferPool", address(pool));
        vm.serializeAddress(obj, "withdrawalPool", address(withdrawalPool));
        vm.serializeAddress(obj, "PufferProtocol", address(proxy));

        string memory finalJson = vm.serializeString(obj, "", "");

        vm.writeJson(finalJson, "./output/puffer.json");

        // console.log(address(withdrawalPool), "<-- WithdrawalPool");
        // console.log(address(pool), "<-- Puffer pool");
        // console.log(address(proxy), "<-- PufferProtocol (main contract)");

        return (pufferProtocol, pool, accessManager);
    }
}
