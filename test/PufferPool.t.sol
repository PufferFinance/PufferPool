// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test, console } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { Enum } from "safe-contracts/common/Enum.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { PufferPoolMockUpgrade } from "test/mocks/PufferPoolMockUpgrade.sol";
import { DeployPufferPool } from "scripts/DeployPufferPool.s.sol";
import { DeployBeacon } from "scripts/DeployBeacon.s.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";

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
    event DepositRateChanged(uint256 oldValue, uint256 newValue);
    event ETHProvisioned(address eigenPodProxy, bytes blsPubKey, uint256 timestamp);

    PufferPool pool;
    WithdrawalPool withdrawalPool;
    SafeProxyFactory proxyFactory;
    Safe safeImplementation;
    UpgradeableBeacon beacon;

    bytes32 private constant _PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    struct _TestTemps {
        address owner;
        address to;
        uint256 amount;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 privateKey;
        uint256 nonce;
    }

    function _testTemps(string memory seed, address to, uint256 amount, uint256 deadline)
        internal
        returns (_TestTemps memory t)
    {
        (t.owner, t.privateKey) = makeAddrAndKey(seed);
        t.to = to;
        t.amount = amount;
        t.deadline = deadline;
    }

    function setUp() public {
        (, beacon) = new DeployBeacon().run(true);
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool, withdrawalPool) =
            new DeployPufferPool().run(address(beacon), address(proxyFactory), address(safeImplementation));
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

        vm.expectRevert("Initializable: contract is already initialized");
        pool.initialize({
            safeProxyFactory: address(proxyFactory),
            safeImplementation: address(safeImplementation),
            treasuryOwners: new address[](0),
            withdrawalPool: address(123),
            guardianSafeModule: address(555123)
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
        address[] memory owners = new address[](2);
        owners[0] = makeAddr("guardian");
        owners[1] = makeAddr("guardian2");

        Safe safe = pool.createGuardianAccount({ guardiansWallets: owners, threshold: owners.length });
        assertTrue(safe.isOwner(owners[0]), "bad owner0");
        assertTrue(safe.isOwner(owners[1]), "bad owner1");
        assertTrue(safe.isOwner(address(pool)), "bad owner");
        assertEq(safe.getThreshold(), 2, "threshold");

        GuardianModule module = pool.getGuardianModule();

        address enclaveAddress = 0x8D88EDeFb5Cb196086068AEB73AC789F613B59F7;
        bytes memory pubKey =
            hex"a091f34f8e90ce7eb0f2ca31a3f12e98dbbdffcae36da273d2fe701b3b14d83a492a4704c0ac4a550308faf0eac6384e";

        vm.prank(owners[0]);
        module.rotateGuardianKeys(address(safe), 0, pubKey, "");

        // assert guardian key is good
        bool isGuardianEnclave = module.isGuardiansEnclaveAddress(payable(address(safe)), enclaveAddress);
        assertTrue(isGuardianEnclave, "failed to rotate keys");

        vm.expectRevert(IPufferPool.GuardiansAlreadyExist.selector);
        pool.createGuardianAccount({ guardiansWallets: owners, threshold: owners.length });
    }

    function getMappingValue(address targetContract, uint256 mapSlot, address key) public view returns (uint256) {
        bytes32 slotValue = vm.load(targetContract, keccak256(abi.encode(key, mapSlot)));
        return uint256(slotValue);
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

    // Deposits ETH and tries to get half of that back
    function testDepositAndWithdrawal() public {
        uint256 depositAmount = 100 ether;
        address pufETHRecipient = makeAddr("pufETHRecipient");

        assertEq(pool.balanceOf(pufETHRecipient), 0, "recipient pufETH amount before deposit");

        // This is the only depositor in our pool, meaning he gets 1:1 pufETH for depositing
        pool.depositETH{ value: depositAmount }(pufETHRecipient);

        uint256 pufETHRecipientBalance = pool.balanceOf(pufETHRecipient);

        assertEq(depositAmount, pufETHRecipientBalance, "1:1 ratio");

        // Our WithdrawalPool is empty, so we need to give it some ETH so that it can handle withdrawals
        uint256 liquidityAmount = 1_000_000 ether;

        // Give eth to eth pool so that it has liquidity
        vm.deal(address(withdrawalPool), liquidityAmount);

        // Calculate the expected amount out
        uint256 expectedAmount = (depositAmount + liquidityAmount) / 2;

        vm.startPrank(pufETHRecipient);
        // 2 step withdrawal
        // 1 approve pufETH to withdrawal pool
        pool.approve(address(withdrawalPool), type(uint256).max);

        WithdrawalPool.Permit memory permit;
        permit.owner = pufETHRecipient;
        permit.amount = pufETHRecipientBalance / 2;

        // 2. withdraw
        withdrawalPool.withdrawETH(pufETHRecipient, permit);

        assertEq(expectedAmount, pufETHRecipient.balance, "amounts don't match");
    }

    // Deposits ETH and tries to get half of that back via permit signature
    function testDepositAndWithdrawalWithPermit() public {
        uint256 depositAmount = 100 ether;
        string memory addressSeed = "pufETHDepositor";

        address pufETHDepositor = makeAddr(addressSeed);

        assertEq(pool.balanceOf(pufETHDepositor), 0, "recipient pufETH amount before deposit");

        // This is the only depositor in our pool, meaning he gets 1:1 pufETH for depositing
        pool.depositETH{ value: depositAmount }(pufETHDepositor);

        uint256 pufETHRecipientBalance = pool.balanceOf(pufETHDepositor);

        assertEq(depositAmount, pufETHRecipientBalance, "1:1 ratio");

        // Our WithdrawalPool is empty, so we need to give it some ETH so that it can handle withdrawals
        uint256 liquidityAmount = 1_000_000 ether;

        // Give eth to eth pool so that it has liquidity
        vm.deal(address(withdrawalPool), liquidityAmount);

        // Calculate the expected amount out
        uint256 expectedAmount = (depositAmount + liquidityAmount) / 2;

        vm.startPrank(pufETHDepositor);

        _TestTemps memory temp =
            _testTemps(addressSeed, address(withdrawalPool), pufETHRecipientBalance / 2, block.timestamp);

        // Do a gasless signature
        WithdrawalPool.Permit memory permit = _signPermit(temp);

        // Create a new recipient address and withdraw to it
        address pufETHRecipient = makeAddr("recipient");

        // Approve is actually a permit signature
        withdrawalPool.withdrawETH(pufETHRecipient, permit);

        assertEq(expectedAmount, pufETHRecipient.balance, "recipient didnt get any ETH");
    }

    // // Test multiple deposits, fake rewards, fake slashing and withdrawal of pufETH -> ETH
    // function testMultipleDeposits() public {
    //     address alice = makeAddr("alice");
    //     address bob = makeAddr("bob");

    //     uint256 aliceAmount = 100 ether;
    //     pool.depositETH{ value: aliceAmount }(alice);

    //     uint256 alicePufETHBalance = pool.balanceOf(alice);
    //     assertEq(alicePufETHBalance, aliceAmount); // first depositor got 1:1 conversion rate because totalSupply of pufETH is 0

    //     // 100 ETH deposited, 100 pufETH minted - 1:1 rate

    //     // Send fake rewards to pool
    //     // pool now has 25 ETH
    //     (bool success,) = payable(address(pool)).call{ value: 25 ether }("");
    //     require(success, "rewards failed");

    //     // Pool before deposit has 125 ETH and 100 pufETH total supply
    //     // conversion rate is 1.25
    //     uint256 bobAmount = 100 ether;
    //     pool.depositETH{ value: bobAmount }(bob);

    //     // Pool now has 225 ETH (fake rewards + alice deposit + bob deposit)
    //     assertEq(225 ether, address(pool).balance, "pool eth amount first check");

    //     // Check that the bob got the right amount of pufETH tokens
    //     uint256 bobPufETHBalance = pool.balanceOf(bob);
    //     assertEq(bobPufETHBalance, 80 ether);

    //     // Check the total supply 100 pufETH from alice and 80 from bob
    //     assertEq(pool.totalSupply(), 180 ether, "pufETH total supply");

    //     // Send fake rewards to pool
    //     (success,) = payable(address(pool)).call{ value: 45 ether }("");
    //     require(success, "rewards failed");

    //     // 270 ETH in the pool and 180 pufETH mean 1.5 conversion rate
    //     assertEq(pool.getPufETHtoETHExchangeRate(), 1.5 ether, "conversion rate"); // conversion rate should be 1.5

    //     // Alice withdraws 70 pufETH for 105 ETH
    //     vm.prank(alice);
    //     pool.withdrawETH(alice, 70 ether);

    //     assertEq(105 ether, alice.balance, "alice amount");

    //     // Fake slashing of the pool
    //     vm.prank(address(pool));
    //     (success,) = payable(address(0)).call{ value: 65 ether }("");
    //     require(success, "fake slashing");

    //     assertEq(100 ether, address(pool).balance, "pool eth amount");
    //     assertEq(pool.totalSupply(), 110 ether, "pufETH total supply second check");

    //     // 100 eth / 110 pufETH => 0.90909090909090909 exchange rate
    //     assertEq(pool.getPufETHtoETHExchangeRate(), 0.90909090909090909 ether, "conversion rate after fake slashing"); // ~0.9

    //     vm.prank(bob);
    //     pool.withdrawETH(bob, 10 ether); // withdraw 10pufETH -> ETH

    //     // Bob should get ~9 ETH
    //     assertEq(9.0909090909090909 ether, bob.balance, "bob amount");

    //     // Assert leftover
    //     assertEq(100 ether - 9.0909090909090909 ether, address(pool).balance, "pool eth amount last check");
    //     assertEq(pool.totalSupply(), 100 ether, "pufETH total supply last check");

    //     // Withdraw the remaining pufETH, zeroing out ETH and pufETH total supply
    //     vm.prank(alice);
    //     pool.withdrawETH(alice, 30 ether);

    //     vm.prank(bob);
    //     pool.withdrawETH(bob, 70 ether);

    //     assertEq(0, address(pool).balance, "pool eth amount");
    //     assertEq(pool.totalSupply(), 0, "pufETH total supply last check");
    // }

    // Test provisioning pod ETH and starting the validation process
    function testProvisionPodETH() public {
        address[] memory owners = new address[](1);
        owners[0] = address(this); // set owner as this address, so that we don't `unauthorized` reverts

        IPufferPool.ValidatorKeyData memory validatorData = _getMockValidatorKeyData();

        (, IEigenPodProxy proxy) =
            pool.createPodAccountAndRegisterValidatorKey{ value: 16 ether }(owners, 1, validatorData, owners[0]);

        pool.depositETH{ value: 100 ether }(address(this));

        vm.expectEmit(true, true, true, true);
        emit ETHProvisioned(address(proxy), validatorData.blsPubKey, 1);
        pool.provisionPodETH({
            eigenPodProxy: address(proxy),
            pubKey: validatorData.blsPubKey,
            signature: new bytes(0),
            depositDataRoot: bytes32("")
        });
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

    function testSplittingUpTheETH() public {
        (bool success,) = address(pool).call{ value: 100 ether }("");
        assertTrue(success, "failed");

        // Initial values are 5% to treasury
        // 90% of the remainder to deposit pool
        // the rest to the withdrawal pool

        assertEq(pool.getTreasury().balance, 5 ether, "treasury");
        assertEq(address(pool).balance, 85.5 ether, "depositPool");
        assertEq(address(withdrawalPool).balance, 9.5 ether, "withdrawalPool");
    }

    function testSetDepositRate() public {
        uint256 depositRate = 70 * 1 ether; // 70%
        vm.expectEmit(true, true, true, true);
        emit DepositRateChanged(pool.getDepositRate(), depositRate);
        pool.setDepositRate(depositRate);
    }

    // Modified from https://github.com/Vectorized/solady/blob/2ced0d8382fd0289932010517d66efb28b07c3ce/test/ERC20.t.sol
    function _signPermit(_TestTemps memory t) internal view returns (WithdrawalPool.Permit memory p) {
        bytes32 innerHash = keccak256(abi.encode(_PERMIT_TYPEHASH, t.owner, t.to, t.amount, t.nonce, t.deadline));
        bytes32 domainSeparator = pool.DOMAIN_SEPARATOR();
        bytes32 outerHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, innerHash));
        (t.v, t.r, t.s) = vm.sign(t.privateKey, outerHash);

        return WithdrawalPool.Permit({ owner: t.owner, deadline: t.deadline, amount: t.amount, v: t.v, r: t.r, s: t.s });
    }

    function _createSafeContractSignature() internal view returns (bytes memory) {
        return abi.encodePacked(
            bytes(hex"000000000000000000000000"),
            address(this),
            bytes(
                hex"0000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
    }
}
