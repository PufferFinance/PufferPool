// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IntegrationTestHelper } from "../helpers/IntegrationTestHelper.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import "forge-std/console.sol";

contract PufferPoolIntegrationTest is IntegrationTestHelper {
    function setUp() public {
        deployContracts();
    }

    function testgetEigenPodProxy() public {
        // Sanity check
        address bob = makeAddr("bob"); // bob address is -> 0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e

        console.log(bob, "bob addr");
        address bobPod = address(IEigenPodManager(pool.EIGEN_POD_MANAGER()).getPod(bob));
        // bob pod should be 0x0a71F48B3052008eFE486a9EeBF3ab44a62B7703
        // verify on etherscan https://etherscan.io/address/0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338#readProxyContract .getPod(bob)
        assertEq(bobPod, 0x0a71F48B3052008eFE486a9EeBF3ab44a62B7703, "bad bob pod");

        // Validaotr pub key
        bytes memory pubKey =
            bytes(hex"a091f34f8e90ce7eb0f2ca31a3f12e98dbbdffcae36da273d2fe701b3b14d83a492a4704c0ac4a550308faf0eac6381e");

        (address eigenPodProxy, address eigenPod) = pool.getEigenPodProxyAndEigenPod(pubKey);

        bytes[] memory blsEncPrivKeyShares = new bytes[](0);
        bytes[] memory blsPubKeyShares = new bytes[](0);

        IPufferPool.ValidatorKeyData memory validatorData = IPufferPool.ValidatorKeyData({
            blsPubKey: pubKey,
            signature: new bytes(0),
            depositDataRoot: bytes32(""),
            blsEncPrivKeyShares: blsEncPrivKeyShares,
            blsPubKeyShares: blsPubKeyShares,
            blockNumber: 1,
            raveEvidence: new bytes(0)
        });

        address mockPod = makeAddr("mocKpod");
        (address prx) = address(pool.registerValidatorKey{ value: 16 ether }(mockPod, mockPod, validatorData));
        address createdPod = address(IEigenPodManager(pool.EIGEN_POD_MANAGER()).getPod(prx));

        assertEq(eigenPodProxy, prx, "eigen pod prxy mismatch");
        assertEq(eigenPod, createdPod, "address compute failed");
    }
}
