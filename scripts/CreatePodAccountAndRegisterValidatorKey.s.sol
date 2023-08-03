// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { DeployBeacon } from "scripts/DeployBeacon.s.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { Test } from "forge-std/Test.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { DeployPufferPool } from "scripts/DeployPufferPool.s.sol";
import "forge-std/console.sol";

contract CreatePodRegisterKey is Script {
    function run() external {
    	IPufferPool pool = IPufferPool(0x00cEfcd3125E6060A841308330329Be418F8356e);
    	vm.startBroadcast(0x4f9906092cF0aa2A9EafBEF46622A71288378Ca7);

    	// Set up arguments for function call
    	address[] memory podAccountOwners = new address[](1);
    	podAccountOwners[0] = address(0x4f9906092cF0aa2A9EafBEF46622A71288378Ca7); //address(0x3c0437396BA3D9CCc8d41DEDe62Fe161a3dB8e4A);
    	address podRewardsRecipient = address(0x3c0437396BA3D9CCc8d41DEDe62Fe161a3dB8e4A);
    	uint256 podAccountThreshold = 1;
    	IPufferPool.ValidatorKeyData memory data;
    	data.blsPubKey = abi.encodePacked(hex"ac6cf06407329d1975355a801aa02603a6aadd53bd106f3238265dba2e0dc6fe29034fc29921346ff90fa79c308cca2e");
    	data.signature = abi.encodePacked(hex"83b525dcf728d78aa121556790a3df2787c68931f579e94a38d7fa2378a6386187881e5555645f435bcf1a36b32ad628003815490038167110fd395dd8e43dd49c67caef4ba024b47ad2f66ae789f7f43724fe32b764410702faa7838db3149f");
    	data.depositDataRoot = bytes32(abi.encodePacked(hex"a6a6f7fc0456a60feb07a2510d977db39fea11ee1cc6d205eacc095730ce2872"));
    	bytes[] memory blsEncPrivKeyShares;
    	data.blsEncPrivKeyShares = blsEncPrivKeyShares;
    	bytes[] memory blsPubKeyShares = new bytes[](1);
    	blsPubKeyShares[0] = bytes("");
    	data.blsPubKeyShares = blsPubKeyShares;
    	data.blockNumber = 1;
    	// Ignore raveEvidence for now
    	//data.raveEvidence = abi.encode("", "", "", "", "", abi.encodePacked(hex"4242424242424242424242424242424242424242424242424242424242424242"), abi.encodePacked(hex"4242424242424242424242424242424242424242424242424242424242424242"));
    	data.raveEvidence = bytes("");
    	pool.createPodAccountAndRegisterValidatorKey{ value: 16 ether }(podAccountOwners, podAccountThreshold, data, podRewardsRecipient);
    	vm.stopBroadcast();
    }

    // Deploys pool contract instance locally and funds account, used when testing
    function setup() external {
    	PufferPool pool;
	    SafeProxyFactory proxyFactory;
	    Safe safeImplementation;
	    UpgradeableBeacon beacon;

    	(, beacon) = new DeployBeacon().run(true);
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool) = new DeployPufferPool().run(address(beacon), address(proxyFactory), address(safeImplementation));
        vm.deal(address(this), 32 ether);
    }
}