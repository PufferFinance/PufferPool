// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import {Script} from "forge-std/Script.sol";
import {BaseScript} from "scripts/BaseScript.s.sol";
import {SafeProxyFactory} from "safe-contracts/proxies/SafeProxyFactory.sol";
import {Safe} from "safe-contracts/Safe.sol";
import {IEigenPodProxy} from "puffer/interface/IEigenPodProxy.sol";
import {IPufferPool} from "puffer/interface/IPufferPool.sol";
import {BeaconProxy} from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import {UpgradeableBeacon} from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import {DeployBeacon} from "scripts/DeployBeacon.s.sol";
import {EigenPodProxy} from "puffer/EigenPodProxy.sol";
import {PufferPool} from "puffer/PufferPool.sol";
import {Test} from "forge-std/Test.sol";
import {DeploySafe} from "scripts/DeploySafe.s.sol";
import {DeployPufferPool} from "scripts/DeployPufferPool.s.sol";
import {Strings} from "openzeppelin/utils/Strings.sol";
import {CustomJSONBuilder} from "scripts/DeployPuffer.s.sol";
import "forge-std/console.sol";
import "forge-std/StdJson.sol";

using stdJson for string;

// Commandline argument will give path to json file for params, and public key, needed in vm.startBroadcast()
// Example script call (Assumes `PK` environment variable is set to eth private key):
// forge script ./CreatePodAccountAndRegisterValidatorKey.s.sol:CreatePodAndRegisterKey ~/puffer/PufferPool/simulation/ephemery-sim-1/validator-1 --sig 'run(string)' --rpc-url 'https://otter.bordel.wtf/erigon' --broadcast
contract CreatePodAndRegisterKey is BaseScript {
    function _parseRegistrationData(
        string memory json
    )
        internal
        returns (
            IPufferPool pool,
            address[] memory podAccountOwners,
            address podRewardsRecipient,
            uint256 podAccountThreshold,
            IPufferPool.ValidatorKeyData memory data
        )
    {
        // Parse out necessary fields
        address poolAddress = abi.decode(
            vm.parseJson(json, ".poolContract"),
            (address)
        );

        pool = IPufferPool(poolAddress);

        (podAccountOwners) = abi.decode(
            vm.parseJson(json, ".podAccountOwners"),
            (address[])
        );

        (podRewardsRecipient) = abi.decode(
            vm.parseJson(json, ".podRewardsRecipient"),
            (address)
        );

        podAccountThreshold = vm.parseJsonUint(json, ".podAccountThreshold");

        data.blsPubKey = vm.parseJsonBytes(json, ".blsPubKey");

        data.signature = vm.parseJsonBytes(json, ".signature");

        data.depositDataRoot = vm.parseJsonBytes32(json, ".depositDataRoot");

        // For now, don't read blsEncPrivKeyShares from Json, just hardcode empty array (TODO)
        bytes[] memory blsEncPrivKeyShares;
        data.blsEncPrivKeyShares = blsEncPrivKeyShares;

        data.blsPubKeyShares = vm.parseJsonBytesArray(json, ".blsPubKeyShares");

        data.blockNumber = vm.parseJsonUint(json, ".blockNumber");

        // Ignore raveEvidence for now (TODO)
        data.raveEvidence = bytes("");
    }

    function run(string calldata jsonDir) external broadcast {
        string memory pathToJson = string.concat(jsonDir, "/inputs.json");

        // Read in Json file
        string memory json = vm.readFile(pathToJson);

        (
            IPufferPool pool,
            address[] memory podAccountOwners,
            address podRewardsRecipient,
            uint256 podAccountThreshold,
            IPufferPool.ValidatorKeyData memory data
        ) = _parseRegistrationData(json);

        // TODO: Add logic to determine which bond amount to use based on above parsed parameters
        // Hardcoded bond amount and podRewardsRecipient
        uint256 bondAmount = 16 ether;

        Safe podAccount;
        IEigenPodProxy eigenPodProxy;

        console.log(address(pool));
        console.log(podRewardsRecipient);

        (podAccount, eigenPodProxy) = pool
            .createPodAccountAndRegisterValidatorKey{value: bondAmount}({
            podAccountOwners: podAccountOwners,
            podAccountThreshold: podAccountThreshold,
            data: data,
            podRewardsRecipient: podRewardsRecipient
        });

		// Write the EigenPodProxy address to be easily consumed by calling bash script
        vm.writeFile(
            string.concat(jsonDir, "/EigenPodProxy-address"),
            Strings.toHexString(address(eigenPodProxy))
        );
    }
}
