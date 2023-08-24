// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IntegrationTestHelper } from "../helpers/IntegrationTestHelper.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { RaveEvidence } from "puffer/interface/RaveEvidence.sol";

contract PufferPoolIntegrationTest is IntegrationTestHelper {
    address bob = makeAddr("bob"); // bob address is -> 0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e

    function setUp() public {
        deployContracts();
    }

    function testIntegrationCreatePodAccountAndRegisterValidatorKey() public {
        // Sanity check

        address[] memory owners = new address[](1);
        owners[0] = bob;

        assertEq(
            address(pool.EIGEN_POD_MANAGER()),
            address(0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338),
            "wrong address for manager"
        ); // Mainnet manager address

        address bobPod = address(IEigenPodManager(pool.EIGEN_POD_MANAGER()).getPod(bob));
        // bob pod should be 0x0a71F48B3052008eFE486a9EeBF3ab44a62B7703
        // verify on etherscan https://etherscan.io/address/0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338#readProxyContract .getPod(bob)
        assertEq(bobPod, 0x0a71F48B3052008eFE486a9EeBF3ab44a62B7703, "bad bob pod");

        // Validator pub key example
        bytes memory pubKey =
            bytes(hex"a091f34f8e90ce7eb0f2ca31a3f12e98dbbdffcae36da273d2fe701b3b14d83a492a4704c0ac4a550308faf0eac6381e");

        bytes[] memory blsEncPrivKeyShares = new bytes[](0);
        bytes[] memory blsPubKeyShares = new bytes[](0);

        RaveEvidence memory evidence;

        IPufferPool.ValidatorKeyData memory validatorData = IPufferPool.ValidatorKeyData({
            blsPubKey: pubKey,
            signature: new bytes(0),
            depositDataRoot: bytes32(""),
            blsEncryptedPrivKeyShares: blsEncPrivKeyShares,
            blsPubKeyShares: blsPubKeyShares,
            blockNumber: 1,
            evidence: evidence
        });

        (address predictedEigenPodProxy, address predictedEigenPod) = pool.getEigenPodProxyAndEigenPod(owners);

        // Give money to bob
        vm.deal(bob, 100 ether);

        vm.startPrank(bob);
        // Register validator 1
        (, IEigenPodProxy proxy) =
            pool.createPodAccountAndRegisterValidatorKey{ value: 16 ether }(owners, 1, validatorData, bob, "");

        address podAddress = address(IEigenPodManager(pool.EIGEN_POD_MANAGER()).getPod(address(proxy)));

        assertEq(predictedEigenPodProxy, address(proxy), "predicted address is bad");
        assertEq(predictedEigenPod, podAddress, "predicted pod address is bad");

        // Try to Register validator 2 with the same key, it should revert
        vm.expectRevert();
        pool.registerValidatorKey{ value: 16 ether }(proxy, validatorData);

        // Register different key should work
        validatorData.blsPubKey =
            bytes(hex"aaaaaaaaaa90ce7eb0f2ca31a3f12e98dbbdffcae36da273d2fe701b3b14d83a492a4704c0ac4a550308faf0eac6381e");
        pool.registerValidatorKey{ value: 16 ether }(proxy, validatorData);
        vm.stopPrank();
    }
}
