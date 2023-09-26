// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { PufferServiceManager } from "puffer/PufferServiceManager.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { ExecutionRewardsVault } from "puffer/ExecutionRewardsVault.sol";
import { ConsensusVault } from "puffer/ConsensusVault.sol";
import { Script } from "forge-std/Script.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { ERC1967Proxy } from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import { BaseScript } from "scripts/BaseScript.s.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { GuardianModule } from "../src/GuardianModule.sol";
import { console } from "forge-std/console.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { Strings } from "openzeppelin/utils/Strings.sol";


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
 *         forge script scripts/DeployPuffer.s.sol:DeployPuffer -vvvv --rpc-url=$EPHEMERY_RPC_URL --broadcast
 */
contract DeployPuffer is BaseScript {   
    function run() broadcast public returns(PufferServiceManager, PufferPool) {
        address eigenSlasher = vm.envOr("EIGEN_SLASHER", address(0));
        address eigenStrategyManager = vm.envOr("EIGEN_STRATEGY_MANAGER", address(0));

        string memory guardiansDeployment = vm.readFile(string.concat("./output/", Strings.toString(block.chainid), "-guardians.json"));

        PufferServiceManager serviceManagerImpl;

        {
            // PufferTreasury
            address payable treasury = payable(vm.envOr("TREASURY", address(1337)));            
            address payable guardians = payable(stdJson.readAddress(guardiansDeployment, ".guardians"));

            // Puffer Service implementation
            serviceManagerImpl = new PufferServiceManager(Safe(guardians), treasury, IStrategyManager(eigenStrategyManager));
        }
        
        // UUPS proxy for PufferServiceManager
        ERC1967Proxy proxy = new ERC1967Proxy(address(serviceManagerImpl), "");

        PufferServiceManager serviceManager = PufferServiceManager(payable(address(proxy)));
        // Deploy pool
        PufferPool pool = new PufferPool(serviceManager);

        WithdrawalPool withdrawalPool = new WithdrawalPool(pool);

        ExecutionRewardsVault executionRewardsVault = new ExecutionRewardsVault(serviceManager);
        
        ConsensusVault consensusVault = new ConsensusVault(serviceManager);

        // Read guardians module variable
        address payable guardiansModule = payable(stdJson.readAddress(guardiansDeployment, ".guardianModule"));

        // Initialize the Pool
        serviceManager.initialize({pool: pool, withdrawalPool: address(withdrawalPool), executionRewardsVault: address(executionRewardsVault), consensusVault: address(consensusVault), guardianSafeModule: guardiansModule});
        
        string memory obj = "";
        vm.serializeAddress(obj, "pufferServiceManagerImplementation", address(serviceManagerImpl));
        vm.serializeAddress(obj, "pufferPool", address(pool));
        vm.serializeAddress(obj, "withdrawalPool", address(withdrawalPool));
        vm.serializeAddress(obj, "executionRewardsVault", address(executionRewardsVault));
        vm.serializeAddress(obj, "consensusVault", address(consensusVault));

        string memory finalJson = vm.serializeString(obj, "", "");

        vm.writeJson(finalJson, "./output/puffer.json");

        // console.log(address(executionRewardsVault), "<-- ExecutionRewardsVault");
        // console.log(address(withdrawalPool), "<-- WithdrawalPool");
        // console.log(address(pool), "<-- Puffer pool");
        // console.log(address(proxy), "<-- PufferServiceManager (main contract)");

        return (serviceManager, pool);
    }
}