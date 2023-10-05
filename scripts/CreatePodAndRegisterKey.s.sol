// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "scripts/BaseScript.s.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";

/**
 * @title Create Eigen Pod Proxy and register validator key script
 * @author Puffer finance
 * @notice Calls the `createPodAccountAndRegisterValidatorKey` function on PufferPool
 * @dev Example on how to run the script
 *
 *      forge script scripts/CreatePodAndRegisterKey.s.sol:CreatePodAndRegisterKey --rpc-url=$EPHEMERY_RPC_URL --broadcast --sig "run(bytes)" -vvvv 0xa091f34f8e90ce7eb0f2ca31a3f12e98dbbdffcae36da273d2fe701b3b14d83a492a4704c0ac4a550308faf0eac6384e
 */
contract CreatePodAndRegisterKey is BaseScript {
    /**
     * @param pubKey Is the validator pubKey
     */
    function run(bytes calldata pubKey) external broadcast {
        address[] memory owners = new address[](1);
        owners[0] = _broadcaster;

        // Use empty object
        IPufferPool.ValidatorKeyData memory validatorData = IPufferPool.ValidatorKeyData({
            blsPubKey: pubKey,
            signature: new bytes(0),
            depositDataRoot: bytes32(""),
            blsEncPrivKeyShares: new bytes[](0),
            blsPubKeyShares: new bytes[](0),
            blockNumber: block.number,
            raveEvidence: new bytes(0)
        });

        // Hardcoded bond amount and podRewardsRecipient
        uint256 bondAmount = 16 ether;

        _pufferPool.createPodAccountAndRegisterValidatorKey{ value: bondAmount }({
            podAccountOwners: owners,
            podAccountThreshold: owners.length,
            data: validatorData,
            podRewardsRecipient: _broadcaster
        });
    }
}
