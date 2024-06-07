// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { L1RewardRegistry } from "puffer/l2/L1RewardRegistry.sol";
import { L2RewardManager } from "puffer/l2/L2RewardManager.sol";

import { NoImplementation } from "pufETH/NoImplementation.sol";

// forge script script/DeployL1AndL2.s.sol:DeployL1AndL2 --rpc-url=$EPHEMERY_RPC_URL
contract DeployL1AndL2 is BaseScript {
    address constant l1Connext = 0x445fbf9cCbaf7d557fd771d56937E94397f43965;
    address constant l1Token = 0x7336C54D07F7F4d564AC5883a7Abb72CfF7c6D6b;
    address constant l1XToken = 0x2B4aaFe533149f9269296868c2178b3c323B7F01;
    address constant lockBox = 0x679d66E98A5a9296d1b595696C6adE5C0382f756;
    uint32 constant destinationDomain = 1633842021;

    address constant l2Connext = 0x1780Ac087Cbe84CA8feb75C0Fb61878971175eb8;
    address constant l2XToken = 0x3dC898c2db965851e64e3621579c53019C70338C;

    function run() public broadcast {
        _deployL1RewardRegistry();
        // _deployL2RewardManager();
    }

    function _deployL1RewardRegistry() internal {
        L1RewardRegistry rewardRegistry = new L1RewardRegistry(l1Connext, l1Token, l1XToken, lockBox, destinationDomain);

        rewardRegistry.setL2RewardManager(0x885E1f36972579EB5D0E9C82C9E930Cf686eD02d);
        
        console.log("L1RewardRegistry", address(rewardRegistry));
    }

    // 0.000036

    function _deployL2RewardManager() internal {
        L2RewardManager rewardManager = new L2RewardManager(l2Connext, l2XToken);

                console.log("L2RewardManager", address(rewardManager));

    }
}
