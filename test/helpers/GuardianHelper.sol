// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { GuardianModule } from "puffer/GuardianModule.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { Test } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { RaveEvidence } from "puffer/interface/RaveEvidence.sol";
import { DeployBeacon } from "scripts/DeployBeacon.s.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { DeployPufferPool } from "scripts/DeployPufferPool.s.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";

contract GuardianHelper is Test {
    // In our test setup we have 3 guardians and 3 guaridan enclave keys
    uint256[] guardiansEnclavePks;
    address guardian1;
    uint256 guardian1PK;
    address guardian2;
    uint256 guardian2PK;
    address guardian3;
    uint256 guardian3PK;
    address guardian1Enclave;
    uint256 guardian1PKEnclave;
    // PubKey is hardcoded because we are creating guardian enclaves deterministically
    bytes guardian1EnclavePubKey =
        hex"048289b999a1a6bc0cc6550ea018d03adee9bfeae6441e53e2e5eed22232a2b8f2d87cf1619c263971a6ada43f7310f37f473de7262ab63778fe3a859c68dc2e27";
    address guardian2Enclave;
    uint256 guardian2PKEnclave;
    bytes guardian2EnclavePubKey =
        hex"0440ba2fa6602bdb09e40d8b400b0c82124c14c8666659c0c78d8e474f3e230d92597cd4811484e1a15d6886745ed6d3fbde7e66f1376e396d8d4e8fa67458a140";
    address guardian3Enclave;
    uint256 guardian3PKEnclave;
    bytes guardian3EnclavePubKey =
        hex"049777a708d71e0b211eff7d44acc9d81be7bbd1bffdc14f60e784c86b64037c745b82cc5d9da0e93dd96d2fb955c32239b2d1d56a456681d4cef88bd603b9b407";

    PufferPool pool;
    WithdrawalPool withdrawalPool;
    SafeProxyFactory proxyFactory;
    Safe safeImplementation;
    UpgradeableBeacon beacon;

    function setUp() public virtual {
        // Create Guardian wallets
        (guardian1, guardian1PK) = makeAddrAndKey("guardian1");
        (guardian1Enclave, guardian1PKEnclave) = makeAddrAndKey("guardian1enclave");
        guardiansEnclavePks.push(guardian1PKEnclave);
        (guardian2, guardian2PK) = makeAddrAndKey("guardian2");
        (guardian2Enclave, guardian2PKEnclave) = makeAddrAndKey("guardian2enclave");
        guardiansEnclavePks.push(guardian2PKEnclave);
        (guardian3, guardian3PK) = makeAddrAndKey("guardian3");
        (guardian3Enclave, guardian3PKEnclave) = makeAddrAndKey("guardian3enclave");
        guardiansEnclavePks.push(guardian3PKEnclave);

        (, beacon) = new DeployBeacon().run(true);
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool, withdrawalPool) =
            new DeployPufferPool().run(address(beacon), address(proxyFactory), address(safeImplementation));
        vm.label(address(pool), "PufferPool");
    }

    // Internal function to create guardian account and register enclave addresses
    function _createGuardians() internal returns (Safe, address[] memory) {
        // Register 3 guardians
        address[] memory owners = new address[](3);
        owners[0] = guardian1;
        owners[1] = guardian2;
        owners[2] = guardian3;

        bytes memory data = abi.encodeCall(GuardianModule.enableMyself, ());

        // Try passing in different calldata
        vm.expectRevert();
        Safe guardianAccount =
            pool.createGuardianAccount({ guardiansWallets: owners, threshold: owners.length, data: "0x1235" });

        guardianAccount = pool.createGuardianAccount({ guardiansWallets: owners, threshold: owners.length, data: data });

        // Assert 3 guardians
        assertTrue(guardianAccount.isOwner(owners[0]), "bad owner 1");
        assertTrue(guardianAccount.isOwner(owners[1]), "bad owner 2");
        assertTrue(guardianAccount.isOwner(owners[2]), "bad owner 3");
        assertEq(guardianAccount.getThreshold(), 3, "threshold");

        GuardianModule module = pool.getGuardianModule();
        assertEq(address(module.pool()), address(pool), "module pool address is wrong");

        vm.expectRevert(IPufferPool.GuardiansAlreadyExist.selector);
        pool.createGuardianAccount({ guardiansWallets: owners, threshold: owners.length, data: data });

        // TODO: generate mock data for this
        RaveEvidence memory evidence;

        // Register enclave keys for guardians
        vm.prank(owners[0]);
        module.rotateGuardianKey(address(guardianAccount), 0, guardian1EnclavePubKey, evidence);
        vm.prank(owners[1]);
        module.rotateGuardianKey(address(guardianAccount), 0, guardian2EnclavePubKey, evidence);
        vm.prank(owners[2]);
        module.rotateGuardianKey(address(guardianAccount), 0, guardian3EnclavePubKey, evidence);

        assertTrue(
            module.isGuardiansEnclaveAddress(payable(address(guardianAccount)), owners[0], guardian1Enclave),
            "bad enclave address"
        );
        assertTrue(
            module.isGuardiansEnclaveAddress(payable(address(guardianAccount)), owners[1], guardian2Enclave),
            "bad enclave address"
        );
        assertTrue(
            module.isGuardiansEnclaveAddress(payable(address(guardianAccount)), owners[2], guardian3Enclave),
            "bad enclave address"
        );

        assertTrue(address(pool.getGuaridnasMultisig()) != address(0), "guardians getter");

        return (guardianAccount, owners);
    }
}
