// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test, console } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { PufferPoolMockUpgrade } from "test/mocks/PufferPoolMockUpgrade.sol";
import { DeployPufferPool } from "scripts/DeployPufferPool.s.sol";
import { DeployBeacon } from "scripts/DeployBeacon.s.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";

contract MockPodOwned {
    function isOwner(address) external pure returns (bool) {
        return true;
    }
}

contract MockPodNotOwned {
    function isOwner(address) external pure returns (bool) {
        return false;
    }
}

contract PufferPoolTest is Test {
    PufferPool pool;
    SafeProxyFactory proxyFactory;
    Safe safeImplementation;
    UpgradeableBeacon beacon;
    address treasuryOwnerMock = makeAddr("treasuryOwnerMock");

    uint256 VALIDATOR_BOND = 2 ether;

    function setUp() public {
        (, beacon) = new DeployBeacon().run();
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool) = new DeployPufferPool().run(address(beacon), address(proxyFactory), address(safeImplementation));
        vm.label(address(pool), "PufferPool");
    }

    // Internal function for creating a Validator Data
    function _getMockValidatorKeyData() internal pure returns (IPufferPool.ValidatorKeyData memory) {
        bytes[] memory newSetOfPubKeys = new bytes[](1);
        newSetOfPubKeys[0] = bytes("key1");

        // key length must be 48 bytes
        bytes memory pubKey = new bytes(48);

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

        return validatorData;
    }

    // Test setup
    function testSetup() public {
        assertEq(pool.name(), "Puffer ETH");
        assertEq(pool.symbol(), "pufETH");
        assertEq(pool.paused(), false, "paused");
        assertEq(address(this), pool.owner(), "owner");
        assertEq(pool.getSafeImplementation(), address(safeImplementation), "safe impl");
        assertEq(pool.getSafeProxyFactory(), address(proxyFactory), "proxy factory");

        address[] memory treasuryOwners = new address[](1);
        treasuryOwners[0] = treasuryOwnerMock;

        vm.expectRevert("Initializable: contract is already initialized");
        pool.initialize({
            safeProxyFactory: address(proxyFactory),
            safeImplementation: address(safeImplementation),
            treasuryOwners: treasuryOwners
        });
    }

    // Test smart contract upgradeability (UUPS)
    function testUpgrade() public {
        vm.expectRevert();
        uint256 result = PufferPoolMockUpgrade(payable(address(pool))).returnSomething();

        PufferPoolMockUpgrade newImplementation = new PufferPoolMockUpgrade(address(beacon));
        pool.upgradeTo(address(newImplementation));

        result = PufferPoolMockUpgrade(payable(address(pool))).returnSomething();

        assertEq(result, 1337);
    }

    // Pause
    function testPause() public {
        assertEq(pool.paused(), false, "!paused");
        pool.pause();
        assertEq(pool.paused(), true, "paused");
    }

    // Resume
    function testResume() public {
        pool.pause();
        assertEq(pool.paused(), true, "paused");
        pool.resume();
        assertEq(pool.paused(), false, "resunmed");
    }

    // Change treasury
    function testChangeTreasury(address newTreasury) public {
        pool.changeTreasury(newTreasury);
        assertEq(pool.getTreasury(), newTreasury, "treasury didnt change");
    }

    // Create guardian account
    function testCreateGuardianAccount() public {
        address[] memory owners = new address[](1);

        owners[0] = address(this);

        Safe safe = pool.createGuardianAccount({ guardiansWallets: owners, threshold: owners.length });
        assertTrue(safe.isOwner(address(this)), "bad owner");
        assertEq(safe.getThreshold(), 1, "threshold");

        vm.expectRevert(IPufferPool.GuardiansAlreadyExist.selector);
        pool.createGuardianAccount({ guardiansWallets: owners, threshold: owners.length });
    }

    // Test creating pod account
    function testCreatePodAccount(address owner1) public {
        vm.assume(owner1 != address(0)); // address(0) can't be used
        vm.assume(owner1 != address(1)); // address(1) can't be used as it is special address in {Safe}

        address[] memory owners = new address[](1);
        owners[0] = owner1;

        Safe safe = pool.createPodAccount({ podAccountOwners: owners, threshold: owners.length });

        assertTrue(safe.isOwner(address(owner1)), "bad owner");
        assertEq(safe.getThreshold(), 1, "safe threshold");
    }

    // Fuzz test for creating Pod account and registering one validator key
    function testCreatePodAccountAndRegisterValidatorKey(address owner1) public {
        vm.assume(owner1 != address(0)); // address(0) can't be used
        vm.assume(owner1 != address(1)); // address(1) is a special ddress in {Safe}

        address[] memory owners = new address[](2);

        owners[0] = owner1;
        owners[1] = address(this); // set owner as this address, so that we don't `unauthorized` reverts

        IPufferPool.ValidatorKeyData memory validatorData = _getMockValidatorKeyData();
        // bad pub key length, it needs to be 48
        bytes memory badPubKey = new bytes(45);
        validatorData.blsPubKey = badPubKey;

        address rewardsRecipient = makeAddr("rewardsRecipient");

        // Registering key from unauthorized msg.sender should fail
        vm.expectRevert(IPufferPool.InvalidBLSPubKey.selector);
        pool.createPodAccountAndRegisterValidatorKey(owners, 2, validatorData, rewardsRecipient);

        // set key to correct length
        validatorData.blsPubKey = new bytes(48);

        // Invalid amount revert
        vm.expectRevert(IPufferPool.InvalidAmount.selector);
        (Safe safe, IEigenPodProxy proxy) =
            pool.createPodAccountAndRegisterValidatorKey{ value: 13 ether }(owners, 2, validatorData, rewardsRecipient);

        // Success
        (safe, proxy) =
            pool.createPodAccountAndRegisterValidatorKey{ value: 16 ether }(owners, 2, validatorData, rewardsRecipient);

        assertTrue(safe.isOwner(address(owner1)), "bad owner");
        assertTrue(safe.isOwner(address(this)), "bad owner2");
        assertEq(safe.getThreshold(), 2, "safe threshold");

        assertEq(proxy.getPodProxyOwner(), address(safe), "eigen pod proxy owner");
        assertEq(proxy.getPodProxyManager(), address(pool), "eigen pod proxy manager");
    }

    function testCreatePodAccountAlija() public {
        address[] memory owners = new address[](2);

        owners[0] = makeAddr("owner1");
        owners[1] = address(this); // set owner as this address, so that we don't `unauthorized` reverts

        Safe safe = pool.createPodAccount(owners, 2);

        IPufferPool.ValidatorKeyData memory validatorData = _getMockValidatorKeyData();

        (address precomputedEigenPodProxyAddress, address eigenPod) =
            pool.getEigenPodProxyAndEigenPod(validatorData.blsPubKey);

        IEigenPodProxy proxy =
            pool.registerValidatorKey{ value: 16 ether }(address(safe), makeAddr("rewardsRecipientMock"), validatorData);

        assertEq(address(proxy), precomputedEigenPodProxyAddress, "precompute failed");
        assertEq(proxy.getPodProxyOwner(), address(safe), "did not set owner");
        assertEq(precomputedEigenPodProxyAddress, eigenPod, "in mock they should match");
    }

    // Fuzz test for depositing ETH to PufferPool
    function testDeposit(address pufETHRecipient, uint256 depositAmount) public {
        vm.assume(pufETHRecipient != address(0));
        depositAmount = bound(depositAmount, 0.01 ether, 1_000_000 ether);

        assertEq(pool.balanceOf(pufETHRecipient), 0, "recipient pufETH amount before deposit");

        pool.depositETH{ value: depositAmount }(pufETHRecipient);

        assertEq(pool.balanceOf(pufETHRecipient), depositAmount, "recipient pufETH amount");
    }

    // Deposits a random amount of ETH, gets pufETH in return, withdraws pufETH
    // should get the deposited ETH amount back
    function testDepositAndWtihdrawal(uint256 depositAmount) public {
        depositAmount = bound(depositAmount, 0.01 ether, 1_000_000 ether);
        address pufETHRecipient = makeAddr("pufETHRecipient");

        assertEq(pool.balanceOf(pufETHRecipient), 0, "recipient pufETH amount before deposit");

        pool.depositETH{ value: depositAmount }(pufETHRecipient);

        uint256 pufETHRecipientBalance = pool.balanceOf(pufETHRecipient);

        vm.startPrank(pufETHRecipient);
        pool.approve(address(pool), pufETHRecipientBalance);

        pool.withdrawETH(pufETHRecipient, pufETHRecipientBalance);

        assertEq(depositAmount, pufETHRecipient.balance, "amounts don't match");
    }

    // Test multiple deposits, fake rewards, fake slashing and withdrawal of pufETH -> ETH
    function testMultipleDeposits() public {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        uint256 aliceAmount = 100 ether;
        pool.depositETH{ value: aliceAmount }(alice);

        uint256 alicePufETHBalance = pool.balanceOf(alice);
        assertEq(alicePufETHBalance, aliceAmount); // first depositor got 1:1 conversion rate because totalSupply of pufETH is 0

        // 100 ETH deposited, 100 pufETH minted - 1:1 rate

        // Send fake rewards to pool
        // pool now has 25 ETH
        (bool success,) = payable(address(pool)).call{ value: 25 ether }("");
        require(success, "rewards failed");

        // Pool before deposit has 125 ETH and 100 pufETH total supply
        // conversion rate is 1.25
        uint256 bobAmount = 100 ether;
        pool.depositETH{ value: bobAmount }(bob);

        // Pool now has 225 ETH (fake rewards + alice deposit + bob deposit)
        assertEq(225 ether, address(pool).balance, "pool eth amount first check");

        // Check that the bob got the right amount of pufETH tokens
        uint256 bobPufETHBalance = pool.balanceOf(bob);
        assertEq(bobPufETHBalance, 80 ether);

        // Check the total supply 100 pufETH from alice and 80 from bob
        assertEq(pool.totalSupply(), 180 ether, "pufETH total supply");

        // Send fake rewards to pool
        (success,) = payable(address(pool)).call{ value: 45 ether }("");
        require(success, "rewards failed");

        // 270 ETH in the pool and 180 pufETH mean 1.5 conversion rate
        assertEq(pool.getPufETHtoETHExchangeRate(), 1.5 ether, "conversion rate"); // conversion rate should be 1.5

        // Alice withdraws 70 pufETH for 105 ETH
        vm.prank(alice);
        pool.withdrawETH(alice, 70 ether);

        assertEq(105 ether, alice.balance, "alice amount");

        // Fake slashing of the pool
        vm.prank(address(pool));
        (success,) = payable(address(0)).call{ value: 65 ether }("");
        require(success, "fake slashing");

        assertEq(100 ether, address(pool).balance, "pool eth amount");
        assertEq(pool.totalSupply(), 110 ether, "pufETH total supply second check");

        // 100 eth / 110 pufETH => 0.90909090909090909 exchange rate
        assertEq(pool.getPufETHtoETHExchangeRate(), 0.90909090909090909 ether, "conversion rate after fake slashing"); // ~0.9

        vm.prank(bob);
        pool.withdrawETH(bob, 10 ether); // withdraw 10pufETH -> ETH

        // Bob should get ~9 ETH
        assertEq(9.0909090909090909 ether, bob.balance, "bob amount");

        // Assert leftover
        assertEq(100 ether - 9.0909090909090909 ether, address(pool).balance, "pool eth amount last check");
        assertEq(pool.totalSupply(), 100 ether, "pufETH total supply last check");

        // Withdraw the remaining pufETH, zeroing out ETH and pufETH total supply
        vm.prank(alice);
        pool.withdrawETH(alice, 30 ether);

        vm.prank(bob);
        pool.withdrawETH(bob, 70 ether);

        assertEq(0, address(pool).balance, "pool eth amount");
        assertEq(pool.totalSupply(), 0, "pufETH total supply last check");
    }

    // Test trying to register a validator key for invalid Eigen pod proxy
    function testRegisterKeyForInvalidEigenPod() public {
        // Use invalid pod address
        address eigenPodProxyMock = address(new MockPodNotOwned());
        vm.expectRevert(IPufferPool.Unauthorized.selector);
        pool.registerValidatorKey{ value: 16 ether }(
            eigenPodProxyMock, makeAddr("rewardsRecipientMock"), _getMockValidatorKeyData()
        );
    }

    // Test trying to register a duplicate vaidator key
    function testRegisterDuplicateKey() public {
        // Use invalid pod address
        address eigenPodProxyMock = address(new MockPodOwned());
        pool.registerValidatorKey{ value: 16 ether }(
            eigenPodProxyMock, makeAddr("rewardsRecipientMock"), _getMockValidatorKeyData()
        );
        vm.expectRevert(IPufferPool.Create2Failed.selector);
        pool.registerValidatorKey{ value: 16 ether }(
            eigenPodProxyMock, makeAddr("rewardsRecipientMock"), _getMockValidatorKeyData()
        );
    }

    // Deposit should revert when trying to deposit too small amount
    function testDepositRevertsForTooSmallAmount() public {
        vm.expectRevert(IPufferPool.InsufficientETH.selector);
        pool.depositETH{ value: 0.005 ether }(makeAddr("recipient"));
    }

    // Setter for {Safe} implementation
    function testChangeSafeImplementation(address mockSafeImplementation) public {
        pool.changeSafeImplementation(mockSafeImplementation);
        assertEq(pool.getSafeImplementation(), mockSafeImplementation);
    }

    // Setter for {Safe} proxy factory
    function testChangeSafeProxyFactory(address mockProxyFactory) public {
        pool.changeSafeProxyFactory(mockProxyFactory);
        assertEq(pool.getSafeProxyFactory(), mockProxyFactory);
    }

    // Setter for execution rewards
    function testSetExecutionCommission(uint256 newValue) public {
        pool.setExecutionCommission(newValue);
        assertEq(pool.getExecutionCommission(), newValue);
    }
    // Setter for consensus rewards

    function testSetConsensusCommission(uint256 newValue) public {
        pool.setConsensusCommission(newValue);
        assertEq(pool.getConsensusCommission(), newValue);
    }

    // Setter for pod avs comission
    function testSetAvsCommision(uint256 newValue) public {
        pool.setAvsCommission(newValue);
        assertEq(pool.getAvsCommission(), newValue);
    }

    // Test configuring the AVS
    function testConfigureAVS(address avs, bool enabled) public {
        uint256 avsComission = 50e16;
        uint8 minBondRequirement = uint8(2);

        IPufferPool.AVSParams memory cfg = IPufferPool.AVSParams({
            podAVSCommission: avsComission,
            minReputationScore: 5,
            minBondRequirement: minBondRequirement,
            enabled: enabled
        });

        pool.changeAVSConfiguration(avs, cfg);
        assertEq(pool.isAVSEnabled(avs), enabled);
        assertEq(pool.getAVSComission(avs), avsComission);
        assertEq(pool.getMinBondRequirement(avs), minBondRequirement);
    }
}
