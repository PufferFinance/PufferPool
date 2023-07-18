// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
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

contract PufferPoolTest is Test {
    PufferPool pool;
    SafeProxyFactory proxyFactory;
    Safe safeImplementation;
    UpgradeableBeacon beacon;

    uint256 VALIDATOR_BOND = 2 ether;

    function setUp() public {
        (, beacon) = new DeployBeacon().run();
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool) = new DeployPufferPool().run(address(beacon), address(proxyFactory), address(safeImplementation));
        vm.label(address(pool), "PufferPool");
    }

    // Test setup
    function testSetup() public {
        assertEq(pool.name(), "Puffer ETH");
        assertEq(pool.symbol(), "pufETH");
        assertEq(pool.paused(), false, "paused");
        assertEq(address(this), pool.owner(), "owner");
        assertEq(pool.getEigenPodValidatorLimit(), 1, "validator limit");
        assertEq(pool.getSafeImplementation(), address(safeImplementation), "safe impl");
        assertEq(pool.getSafeProxyFactory(), address(proxyFactory), "proxy factory");

        vm.expectRevert("Initializable: contract is already initialized");
        pool.initialize({ safeProxyFactory: address(proxyFactory), safeImplementation: address(safeImplementation) });
    }

    // Test smart contract upgradeability (UUPS)
    function testUpgrade() public {
        vm.expectRevert();
        uint256 result = PufferPoolMockUpgrade(payable(address(pool))).returnSomething();

        PufferPoolMockUpgrade newImplementation = new PufferPoolMockUpgrade();
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

    // Create guardian account
    function testCreateGuardianAccount(bytes32 mrenclave) public {
        address[] memory owners = new address[](1);

        owners[0] = address(this);

        Safe safe = pool.createGuardianAccount({
            mrenclave: mrenclave,
            guardiansWallets: owners,
            threshold: owners.length,
            guardiansEnclavePubKeys: new bytes[](0)
        });
        assertTrue(safe.isOwner(address(this)), "bad owner");
        assertEq(safe.getThreshold(), 1, "threshold");

        vm.expectRevert(IPufferPool.GuardiansAlreadyExist.selector);
        pool.createGuardianAccount({
            mrenclave: mrenclave,
            guardiansWallets: owners,
            threshold: owners.length,
            guardiansEnclavePubKeys: new bytes[](0)
        });
    }

    // Test creating pod account
    function testCreatePodAccount(address owner1) public {
        vm.assume(owner1 != address(0)); // address(0) can't be used
        vm.assume(owner1 != address(1)); // address(1) can't be used as it is special address in {Safe}

        address[] memory owners = new address[](1);
        owners[0] = owner1;

        (Safe safe, IEigenPodProxy eigenPodProxy) =
            pool.createPodAccount({ podAccountOwners: owners, threshold: owners.length });

        assertTrue(safe.isOwner(address(owner1)), "bad owner");
        assertEq(safe.getThreshold(), 1, "safe threshold");
        assertEq(eigenPodProxy.podProxyOwner(), address(safe), "eigen pod proxy owner");
    }

    // Fuzz test for creating Pod account and registering one validator key
    function testCreatePodAccountAndRegisterValidatorKey(address owner1, address owner2, bytes calldata pubKey)
        public
    {
        vm.assume(owner1 != address(0)); // address(0) can't be used
        vm.assume(owner2 != address(0));
        vm.assume(owner1 != address(1));
        vm.assume(owner2 != address(1)); // address(1) is special and can't be used in {Safe}
        vm.assume(owner1 != owner2);

        address[] memory owners = new address[](2);

        owners[0] = owner1;
        owners[1] = owner2;

        bytes[] memory pubKeys = new bytes[](1);
        pubKeys[0] = pubKey;

        // Revert if value is not VALIDATOR_BOND
        vm.expectRevert(IPufferPool.InsufficientETH.selector);
        pool.createPodAccountAndRegisterValidatorKeys{ value: 1 ether }({
            podAccountOwners: owners,
            threshold: owners.length,
            pubKeys: pubKeys
        });

        // It should work now
        (Safe safe, IEigenPodProxy eigenPodProxy) = pool.createPodAccountAndRegisterValidatorKeys{
            value: VALIDATOR_BOND
        }({ podAccountOwners: owners, threshold: owners.length, pubKeys: pubKeys });

        assertTrue(safe.isOwner(address(owner1)), "bad owner");
        assertTrue(safe.isOwner(address(owner2)), "bad owner2");
        assertEq(safe.getThreshold(), 2, "safe threshold");
        assertEq(eigenPodProxy.podProxyOwner(), address(safe), "eigen pod proxy owner");
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

    function testCreatePodAndThenRegisterValidatorKey(address owner, bytes calldata pubKey) public {
        vm.assume(owner != address(0)); // address(0) can't be used

        address[] memory owners = new address[](1);
        owners[0] = owner;

        // Create pod account in one transaction
        (Safe safe, IEigenPodProxy eigenPodProxy) =
            pool.createPodAccount({ podAccountOwners: owners, threshold: owners.length });

        bytes[] memory pubKeys = new bytes[](1);
        pubKeys[0] = pubKey;

        // Register validator keys for that EigenPodProxy
        pool.registerValidatorEnclaveKeys{ value: VALIDATOR_BOND }(address(eigenPodProxy), pubKeys);
    }

    // Test trying to register more validator keys than the limit
    function testRegisterValidatorKeyError() public {
        bytes[] memory newSetOfPubKeys = new bytes[](3);
        newSetOfPubKeys[0] = bytes("key1");
        newSetOfPubKeys[1] = bytes("key2");
        newSetOfPubKeys[2] = bytes("key3");

        // We can use mock address because validators for this are performed at a later stage
        address eigenPodProxyMock = makeAddr("podMock");
        vm.expectRevert(IPufferPool.MaximumNumberOfValidatorsReached.selector);
        pool.registerValidatorEnclaveKeys{ value: VALIDATOR_BOND * 3 }(eigenPodProxyMock, newSetOfPubKeys);
    }

    // Test trying to register a validator key for invalid Eigen pod proxy
    function testRegisterKeyForInvalidEigenPod() public {
        bytes[] memory newSetOfPubKeys = new bytes[](1);
        newSetOfPubKeys[0] = bytes("key1");

        // Use invalid pod address
        address eigenPodProxyMock = makeAddr("podMock");
        vm.expectRevert(IPufferPool.InvalidEigenPodProxy.selector);
        pool.registerValidatorEnclaveKeys{ value: VALIDATOR_BOND }(eigenPodProxyMock, newSetOfPubKeys);
    }

    // Test trying to register a duplicate validator key
    function testRegisterDuplicateValidatorKeyError() public {
        address[] memory owners = new address[](1);
        owners[0] = makeAddr("owner");

        // Create pod account in one transaction
        (Safe safe, IEigenPodProxy eigenPodProxy) =
            pool.createPodAccount({ podAccountOwners: owners, threshold: owners.length });

        bytes[] memory newSetOfPubKeys = new bytes[](2);
        newSetOfPubKeys[0] = bytes("key1");
        newSetOfPubKeys[1] = bytes("key1");

        // Increase validator limit before we try to register
        pool.changeEigenPodValidatorLimit(5);

        vm.expectRevert(abi.encodeWithSelector(IPufferPool.DuplicateValidatorKey.selector, newSetOfPubKeys[0]));
        pool.registerValidatorEnclaveKeys{ value: VALIDATOR_BOND * 2 }(address(eigenPodProxy), newSetOfPubKeys);
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

    function testChangeEigenPodValidatorLimit(uint8 newLimit) public {
        pool.changeEigenPodValidatorLimit(newLimit);
        assertEq(pool.getEigenPodValidatorLimit(), newLimit, "setter failed");
    }
}
