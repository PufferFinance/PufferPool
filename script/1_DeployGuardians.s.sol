// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { GuardianModule } from "../src/GuardianModule.sol";
import { EnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { SafeProxy } from "safe-contracts/proxies/SafeProxy.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { Strings } from "openzeppelin/utils/Strings.sol";

// forge script script/1_DeployGuardians.s.sol:DeployGuardians --rpc-url=$EPHEMERY_RPC_URL --sig 'run(address[] calldata, uint256)' "[0x5F9a7EA6A79Ef04F103bfe7BD45dA65476a5155C]" 1
contract DeployGuardians is BaseScript {
    address internal safeProxy;
    address internal safeImplementation;

    function run(address[] calldata guardians, uint256 threshold, bytes calldata emptyData)
        public
        broadcast
        returns (Safe, GuardianModule)
    {
        safeProxy = vm.envOr("SAFE_PROXY_ADDRESS", address(new SafeProxyFactory()));
        safeImplementation = vm.envOr("SAFE_IMPLEMENTATION_ADDRESS", address(new Safe()));

        // Broadcaster is the deployer
        AccessManager accessManager = new AccessManager(_broadcaster);
        vm.label(address(accessManager), "AccessManager");

        EnclaveVerifier verifier = new EnclaveVerifier(100, address(accessManager));

        Safe guardiansSafe = deploySafe(guardians, threshold, address(0), emptyData);

        GuardianModule module = new GuardianModule(verifier, guardiansSafe, address(accessManager));

        string memory obj = "";
        vm.serializeAddress(obj, "guardians", address(guardiansSafe));
        vm.serializeAddress(obj, "accessManager", address(accessManager));
        vm.serializeAddress(obj, "guardianModule", address(module));
        vm.serializeAddress(obj, "safeProxyFactory", address(safeProxy));
        vm.serializeAddress(obj, "safeImplementation", address(safeImplementation));
        vm.serializeAddress(obj, "enclaveVerifier", address(verifier));
        vm.serializeAddress(obj, "pauser", 0x98BDB87fCF3697F4b356C36Cd621ffF94Ee3Aa19);

        string memory finalJson = vm.serializeString(obj, "", "");

        vm.writeJson(finalJson, string.concat("./output/", Strings.toString(block.chainid), "-guardians.json"));

        return (guardiansSafe, module);
    }

    function deploySafe(address[] calldata owners, uint256 threshold, address to, bytes calldata data)
        internal
        returns (Safe)
    {
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
