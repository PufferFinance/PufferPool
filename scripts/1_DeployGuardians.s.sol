// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "scripts/BaseScript.s.sol";
import { GuardianModule } from "../src/GuardianModule.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { SafeProxy } from "safe-contracts/proxies/SafeProxy.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { console } from "forge-std/console.sol";
import { Strings } from "openzeppelin/utils/Strings.sol";

// forge script scripts/1_DeployGuardians.s.sol:DeployGuardians --rpc-url=$EPHEMERY_RPC_URL --sig 'run(address[] calldata, uint256)' "[0x5F9a7EA6A79Ef04F103bfe7BD45dA65476a5155C]" 1
contract DeployGuardians is BaseScript {   

    address safeProxy;
    address safeImplementation;

    function run(address[] calldata guardians, uint256 threshold) broadcast public returns(Safe, GuardianModule) {
        safeProxy = vm.envOr("SAFE_PROXY_ADDRESS", address(new SafeProxyFactory()));
        safeImplementation = vm.envOr("SAFE_IMPLEMENTATION_ADDRESS", address(new Safe()));

        // console.log(safeProxy, "<-- Safe proxy factory");
        // console.log(safeImplementation, "<-- Safe implementation");

        // Deploy module
        GuardianModule module = new GuardianModule();

        // calldata to enable guardian module
        bytes memory data = abi.encodeCall(GuardianModule.enableMyself, ());

        Safe guardiansSafe = this.deploySafe(guardians, threshold, address(module), data);

        // console.log(address(guardiansSafe), "<-- Guardians multisig deployed");

        string memory obj = "";
        vm.serializeAddress(obj, "guardians", address(guardiansSafe));
        vm.serializeAddress(obj, "guardianModule", address(module));
        vm.serializeAddress(obj, "safeProxyFactory", address(safeProxy));
        vm.serializeAddress(obj, "safeImplementation", address(safeImplementation));

        string memory finalJson = vm.serializeString(obj, "", "");

        vm.writeJson(finalJson, string.concat("./output/", Strings.toString(block.chainid), "-guardians.json"));

        return (guardiansSafe, module);
    }

    function deploySafe(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data
    ) public returns (Safe) {
        address zeroAddress = address(0);

        SafeProxy proxy = SafeProxyFactory(safeProxy).createProxyWithNonce({
            _singleton: safeImplementation,
            initializer: abi.encodeCall(
                Safe.setup, (owners, threshold, to, data, zeroAddress, zeroAddress, 0, payable(zeroAddress))
                ),
            saltNonce: uint256(bytes32("guardians"))
        });

        return Safe(payable(address(proxy)));
    }
}