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
import "forge-std/StdJson.sol";

using stdJson for string;

// Commandline argument will give path to json file for params, and public key, needed in vm.startBroadcast()
// Example script call: 
// forge script ./CreatePodAccountAndRegisterValidatorKey.s.sol:CreatePodRegisterKey ./scripts/params.json 0x4f9906092cF0aa2A9EafBEF46622A71288378Ca7 --sig 'run(string, address)'
// forge script ./CreatePodAccountAndRegisterValidatorKey.s.sol:CreatePodRegisterKey ./scripts/params.json 0x4f9906092cF0aa2A9EafBEF46622A71288378Ca7 --sig 'run(string, address)' --rpc-url 'https://otter.bordel.wtf/erigon' --private-key '7557bc2d4cb5fc4fcd1fe6962efc2e3ca1c840195891b72027520555f219323f' --broadcast
contract CreatePodRegisterKey is Script {
    function run(string calldata pathToJson, address publicKey) external {

    	// Read in Json file
    	string memory json = vm.readFile(pathToJson);
    	console.log(json);

    	// Parse out necessary fields
    	address poolAddress;
    	(poolAddress) = abi.decode(vm.parseJson(json, ".poolContract"), (address));
    	IPufferPool pool = IPufferPool(poolAddress);

    	address[] memory podAccountOwners;
    	(podAccountOwners) = abi.decode(vm.parseJson(json, ".podAccountOwners"), (address[]));

    	address podRewardsRecipient;
    	(podRewardsRecipient) = abi.decode(vm.parseJson(json, ".podAccountRecipient"), (address));

    	uint256 podAccountThreshold;
    	podAccountThreshold = vm.parseJsonUint(json, ".podAccountThreshold");

    	IPufferPool.ValidatorKeyData memory data;
    	data.blsPubKey = vm.parseJsonBytes(json, ".blsPubKey");

    	data.signature = vm.parseJsonBytes(json, ".signature");

    	data.depositDataRoot = vm.parseJsonBytes32(json, ".depositDataRoot");

    	// For now, don't read blsEncPrivKeyShares from Json, just hardcode empty array
    	bytes[] memory blsEncPrivKeyShares;
    	data.blsEncPrivKeyShares = blsEncPrivKeyShares;

    	data.blsPubKeyShares = vm.parseJsonBytesArray(json, ".blsPubKeyShares");

    	data.blockNumber = vm.parseJsonUint(json, ".blockNumber");

    	// Ignore raveEvidence for now
    	data.raveEvidence = bytes("");

    	// Start broadcast as publicKey supplied in command line args
    	vm.startBroadcast(publicKey);

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

    // Hardcoded arguments for testing
    function testHardcodedArgs() external {
    	/*
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
    	vm.stopBroadcast();*/
    }
}