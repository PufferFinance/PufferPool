// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ProxyAdmin } from "openzeppelin/proxy/transparent/ProxyAdmin.sol";
import { IBeacon } from "openzeppelin/proxy/beacon/IBeacon.sol";
import {
    ITransparentUpgradeableProxy,
    TransparentUpgradeableProxy
} from "openzeppelin/proxy/transparent/TransparentUpgradeableProxy.sol";
import { Test } from "forge-std/Test.sol";
import { DeployBeacon } from "scripts/DeployBeacon.s.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { EigenPod } from "eigenlayer/pods/EigenPod.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { EigenPodManager } from "eigenlayer/pods/EigenPodManager.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { StrategyManager } from "eigenlayer/core/StrategyManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { DeployPufferPool } from "scripts/DeployPufferPool.s.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";
import { IDelayedWithdrawalRouter } from "eigenlayer/interfaces/IDelayedWithdrawalRouter.sol";
import { SlasherMock } from "test/mocks/SlasherMock.sol";
import { EigenPodManagerMock } from "eigenlayer-test/mocks/EigenPodManagerMock.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { PufferPoolMock } from "test/mocks/PufferPoolMock.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";
import { BytesLib } from "eigenlayer/libraries/BytesLib.sol";
import { DelegationManager } from "eigenlayer/core/DelegationManager.sol";
import { Slasher } from "eigenlayer/core/Slasher.sol";
import { PauserRegistry } from "eigenlayer/permissions/PauserRegistry.sol";
import { IETHPOSDeposit } from "eigenlayer/interfaces/IETHPOSDeposit.sol";
import { ETHPOSDepositMock } from "eigenlayer-test/mocks/ETHDepositMock.sol";

import "eigenlayer/interfaces/IBLSPublicKeyCompendium.sol";
import "eigenlayer/middleware/BLSPublicKeyCompendium.sol";
import "eigenlayer/pods/DelayedWithdrawalRouter.sol";
import "eigenlayer-test/utils/ProofParsing.sol";
//import "eigenlayer-test/EigenLayerDeployer.t.sol";
import "eigenlayer-test/mocks/MiddlewareRegistryMock.sol";
import "eigenlayer-test/mocks/ServiceManagerMock.sol";
import "eigenlayer/libraries/BeaconChainProofs.sol";
import "eigenlayer-test/mocks/BeaconChainOracleMock.sol";
import "eigenlayer-test/mocks/EmptyContract.sol";

contract EigenPodProxyV2Mock is EigenPodProxy {
    constructor() EigenPodProxy(IEigenPodManager(address(0)), ISlasher(address(0))) {
        // do nothing
    }

    function getSomething() external pure returns (uint256 number) {
        return 225883;
    }
}

contract EigenPodMock {
    // Address(1) is the delayed withdrawal mock address
    function delayedWithdrawalRouter() public pure returns (IDelayedWithdrawalRouter) {
        return IDelayedWithdrawalRouter(address(1));
    }
}

contract EigenPodProxyV3Mock is EigenPodProxy {
    IEigenPodManager eigenPodManager = new EigenPodManagerMock();
    ISlasher slasher = new SlasherMock(IStrategyManager(address(0)), IDelegationManager(address(0)));

    constructor() EigenPodProxy(IEigenPodManager(eigenPodManager), slasher) { }

    function init(address payable owner, IPufferPool manager, address payable podRewardsRecipient, uint256 bond)
        public
    {
        _podRewardsRecipient = podRewardsRecipient;
        _podProxyOwner = owner;
        _pool = manager;
        _previousStatus = IEigenPod.VALIDATOR_STATUS.INACTIVE;
        _eigenPodManager.createPod();
        eigenPod = IEigenPod(address(_eigenPodManager.ownerToPod(address(this))));
    }

    function handleQuickWithdraw(uint256 amount) public { }

    function getPreviousStatus() public view returns (IEigenPod.VALIDATOR_STATUS) {
        return _previousStatus;
    }
}

contract EigenPodProxyTest is Test {
    using BytesLib for bytes;

    uint256 internal constant GWEI_TO_WEI = 1e9;

    bytes pubkey = hex"88347ed1c492eedc97fc8c506a35d44d81f27a0c7a1c661b35913cfd15256c0cccbd34a83341f505c7de2983292f2cab";
    uint40 validatorIndex0 = 0;
    uint40 validatorIndex1 = 1;
    //hash tree root of list of validators
    bytes32 validatorTreeRoot;

    //hash tree root of individual validator container
    bytes32 validatorRoot;

    address podOwner = address(42000094993494);

    Vm cheats = Vm(HEVM_ADDRESS);
    DelegationManager public delegation;
    IStrategyManager public strategyManager;
    Slasher public slasher;
    PauserRegistry public pauserReg;

    ProxyAdmin public eigenLayerProxyAdmin;
    IBLSPublicKeyCompendium public blsPkCompendium;
    IEigenPodManager public eigenPodManager;
    IEigenPod public podImplementation;
    IDelayedWithdrawalRouter public delayedWithdrawalRouter;
    IETHPOSDeposit public ethPOSDeposit;
    IBeacon public eigenPodBeacon;
    IBeaconChainOracleMock public beaconChainOracle;
    MiddlewareRegistryMock public generalReg1;
    ServiceManagerMock public generalServiceManager1;
    address[] public slashingContracts;
    address pauser = address(69);
    address unpauser = address(489);
    address podManagerAddress = 0x212224D2F2d262cd093eE13240ca4873fcCBbA3C;
    address podAddress = address(123);
    uint256 stakeAmount = 32e18;
    mapping(address => bool) fuzzedAddressMapping;
    bytes signature;
    bytes32 depositDataRoot;

    bytes32[] withdrawalFields;
    bytes32[] validatorFields;

    PufferPool pool;
    UpgradeableBeacon beacon;
    UpgradeableBeacon rewardsBeacon;
    address payable alice = payable(makeAddr("alice"));
    address payable bob = payable(makeAddr("bob"));
    address beaconOwner = makeAddr("beaconOwner");

    // For Simplifying tests, we are assigning eigenpodMock to address(0)
    address eigenPodMock = address(0);
    // And DelayedWithdrawalRouter to address(1)
    address delayedWithdrawalMock = address(1);

    SafeProxyFactory proxyFactory;
    Safe safeImplementation;
    EigenPodProxy eigenPodProxy;

    mapping(address => bool) _skipAddresses;

    // EIGENPODMANAGER EVENTS
    /// @notice Emitted to notify the update of the beaconChainOracle address
    event BeaconOracleUpdated(address indexed newOracleAddress);

    /// @notice Emitted to notify the deployment of an EigenPod
    event PodDeployed(address indexed eigenPod, address indexed podOwner);

    /// @notice Emitted to notify a deposit of beacon chain ETH recorded in the strategy manager
    event BeaconChainETHDeposited(address indexed podOwner, uint256 amount);

    /// @notice Emitted when `maxPods` value is updated from `previousValue` to `newValue`
    event MaxPodsUpdated(uint256 previousValue, uint256 newValue);

    // EIGENPOD EVENTS
    /// @notice Emitted when an ETH validator stakes via this eigenPod
    event EigenPodStaked(bytes pubkey);

    /// @notice Emitted when an ETH validator's withdrawal credentials are successfully verified to be pointed to this eigenPod
    event ValidatorRestaked(uint40 validatorIndex);

    /// @notice Emitted when an ETH validator's balance is updated in EigenLayer
    event ValidatorBalanceUpdated(uint40 validatorIndex, uint64 newBalanceGwei);

    /// @notice Emitted when an ETH validator is prove to have withdrawn from the beacon chain
    event FullWithdrawalRedeemed(uint40 validatorIndex, address indexed recipient, uint64 withdrawalAmountGwei);

    /// @notice Emitted when a partial withdrawal claim is successfully redeemed
    event PartialWithdrawalRedeemed(
        uint40 validatorIndex, address indexed recipient, uint64 partialWithdrawalAmountGwei
    );

    /// @notice Emitted when restaked beacon chain ETH is withdrawn from the eigenPod.
    event RestakedBeaconChainETHWithdrawn(address indexed recipient, uint256 amount);

    // DELAYED WITHDRAWAL ROUTER EVENTS
    /// @notice Emitted when the `withdrawalDelayBlocks` variable is modified from `previousValue` to `newValue`.
    event WithdrawalDelayBlocksSet(uint256 previousValue, uint256 newValue);

    /// @notice event for delayedWithdrawal creation
    event DelayedWithdrawalCreated(address podOwner, address recipient, uint256 amount, uint256 index);

    /// @notice event for the claiming of delayedWithdrawals
    event DelayedWithdrawalsClaimed(address recipient, uint256 amountClaimed, uint256 delayedWithdrawalsCompleted);

    modifier fuzzedAddress(address addr) virtual {
        cheats.assume(fuzzedAddressMapping[addr] == false);
        _;
    }

    modifier fromPool() {
        vm.startPrank(address(pool));
        _;
        vm.stopPrank();
    }

    modifier fuzzAddresses(address addr) virtual {
        vm.assume(_skipAddresses[addr] == false);
        _;
    }

    uint32 WITHDRAWAL_DELAY_BLOCKS = 7 days / 12 seconds;
    uint256 REQUIRED_BALANCE_WEI = 32 ether;
    uint64 MAX_VALIDATOR_BALANCE_GWEI = 32e9;
    uint64 EFFECTIVE_RESTAKED_BALANCE_OFFSET = 75e7;

    //performs basic deployment before each test
    function setUpEL() public {
        // deploy proxy admin for ability to upgrade proxy contracts
        eigenLayerProxyAdmin = new ProxyAdmin();

        // deploy pauser registry
        address[] memory pausers = new address[](1);
        pausers[0] = pauser;
        pauserReg = new PauserRegistry(pausers, unpauser);

        blsPkCompendium = new BLSPublicKeyCompendium();

        /**
         * First, deploy upgradeable proxy contracts that **will point** to the implementations. Since the implementation contracts are
         * not yet deployed, we give these proxies an empty contract as the initial implementation, to act as if they have no code.
         */
        EmptyContract emptyContract = new EmptyContract();
        delegation = DelegationManager(
            address(new TransparentUpgradeableProxy(address(emptyContract), address(eigenLayerProxyAdmin), ""))
        );
        strategyManager = StrategyManager(
            address(new TransparentUpgradeableProxy(address(emptyContract), address(eigenLayerProxyAdmin), ""))
        );
        slasher =
            Slasher(address(new TransparentUpgradeableProxy(address(emptyContract), address(eigenLayerProxyAdmin), "")));
        delayedWithdrawalRouter = DelayedWithdrawalRouter(
            address(new TransparentUpgradeableProxy(address(emptyContract), address(eigenLayerProxyAdmin), ""))
        );

        ethPOSDeposit = new ETHPOSDepositMock();
        podImplementation = new EigenPod(
                ethPOSDeposit, 
                delayedWithdrawalRouter,
                IEigenPodManager(podManagerAddress),
                MAX_VALIDATOR_BALANCE_GWEI,
                EFFECTIVE_RESTAKED_BALANCE_OFFSET
        );
        eigenPodBeacon = new UpgradeableBeacon(address(podImplementation));

        // this contract is deployed later to keep its address the same (for these tests)
        eigenPodManager = EigenPodManager(
            address(new TransparentUpgradeableProxy(address(emptyContract), address(eigenLayerProxyAdmin), ""))
        );

        // Second, deploy the *implementation* contracts, using the *proxy contracts* as inputs
        DelegationManager delegationImplementation = new DelegationManager(strategyManager, slasher);
        StrategyManager strategyManagerImplementation =
            new StrategyManager(delegation, IEigenPodManager(podManagerAddress), slasher);
        Slasher slasherImplementation = new Slasher(strategyManager, delegation);
        EigenPodManager eigenPodManagerImplementation =
            new EigenPodManager(ethPOSDeposit, eigenPodBeacon, strategyManager, slasher);

        //ensuring that the address of eigenpodmanager doesn't change
        bytes memory code = address(eigenPodManager).code;
        cheats.etch(podManagerAddress, code);
        eigenPodManager = IEigenPodManager(podManagerAddress);

        beaconChainOracle = new BeaconChainOracleMock();
        DelayedWithdrawalRouter delayedWithdrawalRouterImplementation =
            new DelayedWithdrawalRouter(IEigenPodManager(podManagerAddress));

        address initialOwner = address(this);
        // Third, upgrade the proxy contracts to use the correct implementation contracts and initialize them.
        eigenLayerProxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(payable(address(delegation))),
            address(delegationImplementation),
            abi.encodeWithSelector(
                DelegationManager.initialize.selector, initialOwner, pauserReg, 0 /*initialPausedStatus*/
            )
        );
        eigenLayerProxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(payable(address(strategyManager))),
            address(strategyManagerImplementation),
            abi.encodeWithSelector(
                StrategyManager.initialize.selector,
                initialOwner,
                initialOwner,
                pauserReg,
                0, /*initialPausedStatus*/
                0 /*withdrawalDelayBlocks*/
            )
        );
        eigenLayerProxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(payable(address(slasher))),
            address(slasherImplementation),
            abi.encodeWithSelector(Slasher.initialize.selector, initialOwner, pauserReg, 0 /*initialPausedStatus*/ )
        );
        // TODO: add `cheats.expectEmit` calls for initialization events
        eigenLayerProxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(payable(address(eigenPodManager))),
            address(eigenPodManagerImplementation),
            abi.encodeWithSelector(
                EigenPodManager.initialize.selector,
                type(uint256).max, // maxPods
                beaconChainOracle,
                initialOwner,
                pauserReg,
                0 /*initialPausedStatus*/
            )
        );
        uint256 initPausedStatus = 0;
        uint256 withdrawalDelayBlocks = WITHDRAWAL_DELAY_BLOCKS;
        eigenLayerProxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(payable(address(delayedWithdrawalRouter))),
            address(delayedWithdrawalRouterImplementation),
            abi.encodeWithSelector(
                DelayedWithdrawalRouter.initialize.selector,
                initialOwner,
                pauserReg,
                initPausedStatus,
                withdrawalDelayBlocks
            )
        );
        generalServiceManager1 = new ServiceManagerMock(slasher);

        generalReg1 = new MiddlewareRegistryMock(
             generalServiceManager1,
             strategyManager
        );

        cheats.deal(address(podOwner), 5 * stakeAmount);

        fuzzedAddressMapping[address(0)] = true;
        fuzzedAddressMapping[address(eigenLayerProxyAdmin)] = true;
        fuzzedAddressMapping[address(strategyManager)] = true;
        fuzzedAddressMapping[address(eigenPodManager)] = true;
        fuzzedAddressMapping[address(delegation)] = true;
        fuzzedAddressMapping[address(slasher)] = true;
        fuzzedAddressMapping[address(generalServiceManager1)] = true;
        fuzzedAddressMapping[address(generalReg1)] = true;
    }

    function setUpPuffer() public {
        (, beacon) = new DeployBeacon().run(true);

        // Transfer ownership from 'default tx sender' in foundry to beaconOwner
        vm.prank(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
        beacon.transferOwnership(beaconOwner);

        pool = PufferPool(payable(address(new PufferPoolMock())));

        eigenPodProxy = EigenPodProxy(
            payable(
                address(
                    new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (IPufferPool(address(pool)))))
                )
            )
        );

        // Give ETH to pool
        vm.deal(address(pool), 100 ether);

        vm.prank(address(pool));
        eigenPodProxy.setPodProxyOwnerAndRewardsRecipient(alice, alice);

        // In this test setup we set EigenPodMock to address(0)
        EigenPodMock eigenPodMockDeployment = new EigenPodMock();
        // Change the bytecode of address(0) to EigenPodMock bytecode
        vm.etch(eigenPodMock, address(eigenPodMockDeployment).code);

        _skipAddresses[address(pool)] = true;
        _skipAddresses[address(eigenPodProxy)] = true;
        _skipAddresses[eigenPodMock] = true;
        _skipAddresses[delayedWithdrawalMock] = true;
        _skipAddresses[alice] = true;
    }

    function setUpPufferAndEL() public {
        setUpEL();

        // Dploy the eigenpodProxy with the deployed EL contracts
        EigenPodProxy eigenPodProxyImplementation = new EigenPodProxy(IEigenPodManager(eigenPodManager), slasher);
        beacon = new UpgradeableBeacon(address(eigenPodProxyImplementation));

        beacon.transferOwnership(beaconOwner);

        // TODO: Remove mock pool and use real pool?
        pool = PufferPool(payable(address(new PufferPoolMock())));

        eigenPodProxy = EigenPodProxy(
            payable(
                address(
                    new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (IPufferPool(address(pool)))))
                )
            )
        );

        // Give ETH to pool
        vm.deal(address(pool), 100 ether);

        vm.prank(address(pool));
        eigenPodProxy.setPodProxyOwnerAndRewardsRecipient(alice, alice);

        // In this test setup we set EigenPodMock to address(0)
        EigenPodMock eigenPodMockDeployment = new EigenPodMock();
        // Change the bytecode of address(0) to EigenPodMock bytecode
        vm.etch(eigenPodMock, address(eigenPodMockDeployment).code);

        _skipAddresses[address(pool)] = true;
        _skipAddresses[address(eigenPodProxy)] = true;
        _skipAddresses[eigenPodMock] = true;
        _skipAddresses[delayedWithdrawalMock] = true;
        _skipAddresses[alice] = true;
    }

    // Tests the setup
    function testPufferSetup() public {
        setUpPuffer();
        assertEq(eigenPodProxy.getPodProxyManager(), address(pool), "Pool should be the manager");

        assertEq(eigenPodProxy.getPodProxyOwner(), alice, "alice should be the pool proxy owner");
        assertTrue(address(eigenPodProxy.getEigenPodManager()) != address(0), "Eigen pod manager shouldnt be address 0");

        // This acts as a second initializer, so it should revert if we try to call it again
        vm.expectRevert();
        eigenPodProxy.setPodProxyOwnerAndRewardsRecipient(alice, alice);
    }

    function testStaking() public {
        setUpEL();
        cheats.startPrank(podOwner);
        IEigenPod newPod = eigenPodManager.getPod(podOwner);
        cheats.expectEmit(true, true, true, true, address(newPod));
        emit EigenPodStaked(pubkey);
        eigenPodManager.stake{ value: stakeAmount }(pubkey, signature, depositDataRoot);
        cheats.stopPrank();
    }

    // Activates the validator staking
    function testCallStakeShouldWork() public {
        setUpPufferAndEL();
        bytes memory pubKey = abi.encodePacked("1234");
        vm.prank(address(pool));

        eigenPodProxy.callStake{ value: 32 ether }({
            pubKey: pubKey,
            signature: new bytes(0),
            depositDataRoot: bytes32("")
        });
    }

    function testSkimRewards() public {
        setUpPufferAndEL();
        vm.prank(address(pool));

        eigenPodProxy.callStake{ value: 32 ether }({
            pubKey: abi.encodePacked("1234"),
            signature: new bytes(0),
            depositDataRoot: bytes32("")
        });

        IEigenPod pod = eigenPodProxy.eigenPod();
        require(pod.hasRestaked() == false, "Pod should not be restaked");

        // simulate a withdrawal
        cheats.deal(address(pod), stakeAmount);
        cheats.expectEmit(true, true, true, true, address(delayedWithdrawalRouter));
        emit DelayedWithdrawalCreated(
            address(eigenPodProxy),
            address(eigenPodProxy),
            stakeAmount,
            delayedWithdrawalRouter.userWithdrawalsLength(address(eigenPodProxy))
        );
        eigenPodProxy.skimRewards(); //pod.withdrawBeforeRestaking();
        require(
            _getLatestDelayedWithdrawalAmount(address(eigenPodProxy)) == stakeAmount,
            "Payment amount should be stake amount"
        );
        require(
            pod.mostRecentWithdrawalTimestamp() == uint64(block.timestamp),
            "Most recent withdrawal block number not updated"
        );
    }

    function testPostInit() public {
        setUpPufferAndEL();
        require(address(eigenPodProxy.eigenPod()) != address(0), "Eigen Pod should have been created upon Init");
    }

    function testGetEigenPodManager() public {
        setUpPufferAndEL();
        require(
            address(eigenPodProxy.getEigenPodManager()) == address(eigenPodManager),
            "EigenPodManager stored on EigenPodProxy should match deployed"
        );
    }

    // TODO: Test SetPodProxyOwnerAndRewardsRecipient
    // TODO: Also test calling without being owner and expecting failure
    function testSetPodProxyOwnerAndRewardsRecipient() public {
        
    }

    // Test stop registration
    function testReleaseBond() public {
        setUpPuffer();
        assertEq(pool.balanceOf(alice), 0, "alice should not have pufETH");

        // Give 100 pufETH to eigen pod proxy
        deal(address(pool), address(eigenPodProxy), 100 ether);

        // Only PufferPool can call this
        vm.prank(address(pool));
        eigenPodProxy.releaseBond(100 ether);

        assertEq(pool.balanceOf(alice), 100 ether, "alice should get pufETH");
    }

    // Tests the upgrade of two eigen pod proxies
    function testUpgradeBeaconProxy() public {
        testPufferSetup();

        (bool success, bytes memory returndata) =
            address(eigenPodProxy).call(abi.encodeCall(EigenPodProxyV2Mock.getSomething, ()));

        // Expect no return data, but no revert because we have fallback in EigenPodProxy
        // because of that it just returns empty return data
        assertEq(returndata.length, 0);

        address eigenPodProxyTwo = address(
            new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (IPufferPool(address(this)))))
        );

        // // Both Eigen pod proxies should return empty data
        (success, returndata) = address(eigenPodProxyTwo).call(abi.encodeCall(EigenPodProxyV2Mock.getSomething, ()));
        assertEq(returndata.length, 0);

        assertEq(
            EigenPodProxy(payable(eigenPodProxyTwo)).getPodProxyManager(),
            address(this),
            "In production PufferPool will be the manager"
        );

        address newImplementation = address(new EigenPodProxyV2Mock());
        vm.prank(beaconOwner); // It is the owner in test env
        beacon.upgradeTo(newImplementation);

        // // Both eigen pods should return "magic" now that they are upgraded
        assertEq(EigenPodProxyV2Mock(payable(eigenPodProxy)).getSomething(), 225883, "upgrade didnt work for alice");
        assertEq(EigenPodProxyV2Mock(payable(eigenPodProxyTwo)).getSomething(), 225883, "failed upgrade for bob");
    }

    // Tests rewards recipient change, revers if not called by the owner
    function testChangePodRewardsRecipient() public {
        setUpPuffer();
        vm.prank(alice);
        eigenPodProxy.updatePodRewardsRecipient(payable(address(bob)));

        vm.expectRevert(IEigenPodProxy.Unauthorized.selector);
        vm.prank(bob);
        eigenPodProxy.updatePodRewardsRecipient(payable(address(alice)));
    }

    // Execution rewards distirbution
    function testDistributeExecutionRewards(address blockProducer) public fuzzAddresses(blockProducer) {
        setUpPuffer();
        vm.assume(blockProducer != address(0));
        vm.assume(blockProducer != alice && blockProducer != address(pool) && blockProducer != address(eigenPodProxy));
        // For execution rewards msg.sender must be address other than EigenLayer's router
        uint256 poolBalanceBefore = address(pool).balance;

        vm.prank(blockProducer);
        vm.deal(blockProducer, 100 ether);
        (bool success,) = address(eigenPodProxy).call{ value: 100 ether }("");
        require(success, "failed");
        assertEq(alice.balance, 5 ether, "alice did not receive 5% execution reward");
        assertEq(address(pool).balance, poolBalanceBefore + 95 ether, "pool should get the rest");
    }

    /*
    function testExecutionRewardsProxy(uint256 rewardAmount) public {
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool) = new DeployPufferPool().run(address(beacon), address(rewardsBeacon), address(proxyFactory), address(safeImplementation));
        vm.label(address(pool), "PufferPool");

        address payable eigenPodProxyAddress = payable(
            address(
                new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (IPufferPool(address(pool)), 2 ether)))
            )
        );
        EigenPodProxy eigenPodProxy = EigenPodProxy(eigenPodProxyAddress);
        uint256 aliceBalanceBefore = alice.balance;
        uint256 poolBalanceBefore = address(pool).balance;

        // Set Owner and Pod Rewards Recipient
        vm.prank(address(pool));
        eigenPodProxy.setPodProxyOwnerAndRewardsRecipient(alice, alice);

        vm.prank(address(1));
        vm.deal(address(1), rewardAmount);
        assertEq(address(1).balance, rewardAmount);

        payable(address(eigenPodProxy)).call{ value: rewardAmount }("");

        // After sending 1 eth AVS rewards, both alice and the pool should receive funds
        assert(alice.balance >= aliceBalanceBefore);
        assert(address(pool).balance >= poolBalanceBefore);

        // Total funds received should add up to total funds sent to fallback
        assertEq((alice.balance - aliceBalanceBefore) + (address(pool).balance - poolBalanceBefore), rewardAmount);

        // Alice shold get 5% of 1 eth, pool gets the rest
        assertEq(alice.balance - aliceBalanceBefore, (rewardAmount * pool.getExecutionCommission()) / pool.getCommissionDenominator()); // (5 * 10 ** 16 * rewardAmount) / 10 ** 18); (amount * _podProxyManager.getExecutionCommission()) / _podProxyManager.getCommissionDenominator()
        //assertEq(address(pool).balance - poolBalanceBefore, (rewardAmount * (pool.getCommissionDenominator() - pool.getExecutionCommission())) / pool.getCommissionDenominator());
    }

    function testConsensusRewardsActiveProxy() public {
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool) = new DeployPufferPool().run(address(beacon), address(rewardsBeacon), address(proxyFactory), address(safeImplementation));
        vm.label(address(pool), "PufferPool");

        EigenPodProxyV3Mock eigenPodProxy = new EigenPodProxyV3Mock();
        eigenPodProxy.init(alice, IPufferPool(address(pool)), alice, 2 ether);

        uint256 aliceBalanceBefore = alice.balance;
        uint256 poolBalanceBefore = address(pool).balance;

        vm.deal(address(eigenPodProxy), 5 ether);

        eigenPodProxy.distributeConsensusRewards(2 ether);

        assert(alice.balance > aliceBalanceBefore);
        assert(address(pool).balance > poolBalanceBefore);

        // Total funds received should add up to total funds sent to fallback
        assertEq((alice.balance - aliceBalanceBefore) + (address(pool).balance - poolBalanceBefore), 2 ether);

        // Alice shold get 5% of 1 eth, pool gets the rest
        assertEq(alice.balance - aliceBalanceBefore, 10 * 10 ** 16);
        assertEq(address(pool).balance - poolBalanceBefore, 190 * 10 ** 16);
    }

    function testQuickWithdrawProxy() public {
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool) = new DeployPufferPool().run(address(beacon), address(rewardsBeacon), address(proxyFactory), address(safeImplementation));
        vm.label(address(pool), "PufferPool");

        EigenPodProxyV3Mock eigenPodProxy = new EigenPodProxyV3Mock();
        eigenPodProxy.init(alice, IPufferPool(address(pool)), alice, 2 ether);

        vm.deal(address(eigenPodProxy), 2 ether);

        uint256 aliceBalanceBefore = alice.balance;
        uint256 poolBalanceBefore = address(pool).balance;
        // Status is not withdrawn to start
        assert(IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN != eigenPodProxy.getPreviousStatus());

        eigenPodProxy.handleQuickWithdraw(2 ether);

        // Status changes to withdrawn
        assert(IEigenPodWrapper.VALIDATOR_STATUS.WITHDRAWN == eigenPodProxy.getPreviousStatus());
        assert(alice.balance > aliceBalanceBefore);
        assert(address(pool).balance > poolBalanceBefore);
        assertEq(
            (alice.balance - aliceBalanceBefore) + (address(pool).balance - poolBalanceBefore)
                + address(eigenPodProxy).balance,
            2 ether
        );
        // 1 eth will remain on the contract
        assertEq(address(eigenPodProxy).balance, 1 ether);
        assertEq(alice.balance - aliceBalanceBefore, 5 * 10 ** 16);
        assertEq(address(pool).balance - poolBalanceBefore, 95 * 10 ** 16);
    }

    function testCompleteSlowWithdrawProxy() public {
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool) = new DeployPufferPool().run(address(beacon), address(rewardsBeacon), address(proxyFactory), address(safeImplementation));
        vm.label(address(pool), "PufferPool");

        EigenPodProxyV3Mock eigenPodProxy = new EigenPodProxyV3Mock();
        eigenPodProxy.init(alice, IPufferPool(address(pool)), alice, 2 ether);

        // TODO: This should basically just check the pool's withdrawFromProtocol function
    }

    function testRewardsAfterBondWithdrawnProxy() public {
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool) = new DeployPufferPool().run(address(beacon), address(rewardsBeacon), address(proxyFactory), address(safeImplementation));
        vm.label(address(pool), "PufferPool");

        EigenPodProxyV3Mock eigenPodProxy = new EigenPodProxyV3Mock();
        eigenPodProxy.init(alice, IPufferPool(address(pool)), alice, 2 ether);

        eigenPodProxy.setBondWithdrawn(true);

        uint256 aliceBalanceBefore = alice.balance;
        uint256 poolBalanceBefore = address(pool).balance;

        vm.prank(bob);
        vm.deal(bob, 2 ether);
        payable(address(eigenPodProxy)).call{ value: 1 ether }("");

        // Alice should get no funds, and pool should receive everything
        assertEq(alice.balance, aliceBalanceBefore);
        assertEq(address(pool).balance, poolBalanceBefore + 1 ether);
    }
    */

    // Consensus rewards distirbution
    function testDistributeConsensusRewards() public {
        setUpPuffer();
        uint256 poolBalanceBefore = address(pool).balance;

        vm.deal(delayedWithdrawalMock, 100 ether);
        vm.startPrank(delayedWithdrawalMock);
        (bool success,) = address(eigenPodProxy).call{ value: 100 ether }("");
        require(success, "failed");
        assertEq(alice.balance, 10 ether, "alice did not receive 5% consensus reward");
        assertEq(address(pool).balance, poolBalanceBefore + 90 ether, "pool should get the rest");
    }

    function _getLatestDelayedWithdrawalAmount(address recipient) internal view returns (uint256) {
        return delayedWithdrawalRouter.userDelayedWithdrawalByIndex(
            recipient, delayedWithdrawalRouter.userWithdrawalsLength(recipient) - 1
        ).amount;
    }
}
