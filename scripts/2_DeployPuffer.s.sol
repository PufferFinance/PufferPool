// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { ExecutionRewardsPool } from "puffer/ExecutionRewardsPool.sol";
import { Script } from "forge-std/Script.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { ERC1967Proxy } from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import { BaseScript } from "scripts/BaseScript.s.sol";
import { EnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { GuardianModule } from "../src/GuardianModule.sol";
import { console } from "forge-std/console.sol";

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
 *         forge script scripts/2_DeployPuffer.s.sol:DeployPuffer -vvvv --rpc-url=$EPHEMERY_RPC_URL --broadcast
 */
contract DeployPuffer is BaseScript {   
    function run() broadcast public {
        address safeProxy = vm.envOr("SAFE_PROXY_ADDRESS", address(new SafeProxyFactory()));
        address safeImplementation = vm.envOr("SAFE_IMPLEMENTATION_ADDRESS", address(new Safe()));

        address eigenSlasher = vm.envOr("EIGEN_SLASHER", address(0));
        
        // PufferTreasury
        address payable treasury = payable(vm.envOr("TREASURY", address(1337)));

        console.log(treasury, "<-- Puffer Treasury address");
        
        string memory guardiansDeployment = vm.readFile("./output/guardians.json");
        address payable guardians = payable(stdJson.readAddress(guardiansDeployment, ".guardians"));
        address payable guardiansModule = payable(stdJson.readAddress(guardiansDeployment, ".guardianModule"));

        // Deploys Puffer Pool implementation
        PufferPool poolImpl = new PufferPool(treasury, Safe(guardians));
        console.log(address(poolImpl), "<-- Puffer pool implementation");
        // Deploys Proxy contract
        ERC1967Proxy proxy = new ERC1967Proxy(address(poolImpl), "");
        console.log(address(proxy), "<-- Puffer POOL proxy (main contract)");
        // Casts Proxy to PufferPool
        PufferPool pool = PufferPool(payable(address(proxy)));

        EnclaveVerifier verifier = new EnclaveVerifier(100, address(pool));
        console.log(address(verifier), "<-- EnclaveVerifier");

        WithdrawalPool withdrawalPool = new WithdrawalPool(pool);
        console.log(address(withdrawalPool), "<-- WithdrawalPool");

        ExecutionRewardsPool executionRewardsPool = new ExecutionRewardsPool(pool);
        console.log(address(executionRewardsPool), "<-- ExecutionRewardsPool");

        // Initialize the Pool
        pool.initialize({withdrawalPool: address(withdrawalPool), executionRewardsPool: address(executionRewardsPool), guardianSafeModule: guardiansModule, enclaveVerifier: address(verifier), emptyData: ""});
        GuardianModule(guardiansModule).setPufferPool(pool);

        string memory obj = "";
        vm.serializeAddress(obj, "pufferPoolImplementation", address(poolImpl));
        vm.serializeAddress(obj, "pufferPool", address(proxy));
        vm.serializeAddress(obj, "enclaveVerifier", address(verifier));
        vm.serializeAddress(obj, "withdrawalPool", address(withdrawalPool));

        string memory finalJson = vm.serializeString(obj, "", "");

        vm.writeJson(finalJson, "./output/puffer.json");
    }
}