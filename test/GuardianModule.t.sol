// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { SafeDeployer } from "puffer/SafeDeployer.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { Safe, Enum, ModuleManager } from "safe-contracts/Safe.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";

contract GuardianModuleTest is Test, SafeDeployer {
    GuardianModule module;
    Safe safe;

    function setUp() public {
        (SafeProxyFactory proxyFactory, Safe safeImplementation) = new DeploySafe().run();

        address[] memory owners = new address[](1);
        owners[0] = address(this);

        module = new GuardianModule();

        // Deploy safe
        safe = _deploySafe({
            safeProxyFactory: address(proxyFactory),
            safeSingleton: address(safeImplementation),
            saltNonce: 0,
            owners: owners,
            threshold: 1,
            to: address(0),
            data: ""
        });

        // Enable module
        safe.execTransaction({
            to: address(safe),
            value: 0,
            data: abi.encodeCall(ModuleManager.enableModule, address(module)),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            signatures: _createSafeContractSignature()
        });
    }

    function _createSafeContractSignature() internal view returns (bytes memory) {
        return abi.encodePacked(
            bytes(hex"000000000000000000000000"),
            address(this),
            bytes(
                hex"0000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
    }
}
