// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ProofParsing } from "eigenlayer-test/utils/ProofParsing.sol";
import { ProxyAdmin } from "openzeppelin/proxy/transparent/ProxyAdmin.sol";
import { IBeacon } from "openzeppelin/proxy/beacon/IBeacon.sol";
import {
    ITransparentUpgradeableProxy,
    TransparentUpgradeableProxy
} from "openzeppelin/proxy/transparent/TransparentUpgradeableProxy.sol";
import { Test } from "forge-std/Test.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { BeaconProxy } from "openzeppelin/proxy/beacon/BeaconProxy.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { EigenPod } from "eigenlayer/pods/EigenPod.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { EigenPodManager } from "eigenlayer/pods/EigenPodManager.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { StrategyManager } from "eigenlayer/core/StrategyManager.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { IDelayedWithdrawalRouter } from "eigenlayer/interfaces/IDelayedWithdrawalRouter.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { PufferPoolMock } from "test/mocks/PufferPoolMock.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";
import { BytesLib } from "eigenlayer/libraries/BytesLib.sol";
import { DelegationManager } from "eigenlayer/core/DelegationManager.sol";
import { Slasher } from "eigenlayer/core/Slasher.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { PauserRegistry } from "eigenlayer/permissions/PauserRegistry.sol";
import { IETHPOSDeposit } from "eigenlayer/interfaces/IETHPOSDeposit.sol";
import { ETHPOSDepositMock } from "eigenlayer-test/mocks/ETHDepositMock.sol";
import "openzeppelin-upgrades/utils/math/MathUpgradeable.sol";

import "eigenlayer/interfaces/IBLSPublicKeyCompendium.sol";
import "eigenlayer/middleware/BLSPublicKeyCompendium.sol";
import "eigenlayer/pods/DelayedWithdrawalRouter.sol";
import "eigenlayer-test/utils/ProofParsing.sol";
import "eigenlayer-test/mocks/MiddlewareRegistryMock.sol";
import "eigenlayer-test/mocks/ServiceManagerMock.sol";
import "eigenlayer/libraries/BeaconChainProofs.sol";
import "eigenlayer-test/mocks/BeaconChainOracleMock.sol";
import "eigenlayer-test/mocks/EmptyContract.sol";

contract FullWithdrawal is ProofParsing {
    using BytesLib for bytes;

    // Puffer vars

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

    // address -> skip
    mapping(address => bool) _skipAddresses;

    // end puffer vars

    uint256 internal constant GWEI_TO_WEI = 1e9;

    bytes pubkey = hex"88347ed1c492eedc97fc8c506a35d44d81f27a0c7a1c661b35913cfd15256c0cccbd34a83341f505c7de2983292f2cab";
    uint40 validatorIndex0 = 0;
    uint40 validatorIndex1 = 1;
    //hash tree root of list of validators
    bytes32 validatorTreeRoot;

    //hash tree root of individual validator container
    bytes32 validatorRoot;

    address podOwner = address(42000094993494);

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
        vm.assume(fuzzedAddressMapping[addr] == false);
        _;
    }

    uint32 WITHDRAWAL_DELAY_BLOCKS = 7 days / 12 seconds;
    uint256 REQUIRED_BALANCE_WEI = 32 ether;
    uint64 MAX_VALIDATOR_BALANCE_GWEI = 32e9;
    uint64 EFFECTIVE_RESTAKED_BALANCE_OFFSET = 75e7;

    //performs basic deployment before each test
    function setUp() public {
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
        vm.etch(podManagerAddress, code);
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
        // TODO: add `vm.expectEmit` calls for initialization events
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

        vm.deal(address(podOwner), 5 * stakeAmount);

        fuzzedAddressMapping[address(0)] = true;
        fuzzedAddressMapping[address(eigenLayerProxyAdmin)] = true;
        fuzzedAddressMapping[address(strategyManager)] = true;
        fuzzedAddressMapping[address(eigenPodManager)] = true;
        fuzzedAddressMapping[address(delegation)] = true;
        fuzzedAddressMapping[address(slasher)] = true;
        fuzzedAddressMapping[address(generalServiceManager1)] = true;
        fuzzedAddressMapping[address(generalReg1)] = true;
    }

    function testPufferWithdrawalFlow() public {
        // Deploy implementation for
        EigenPodProxy eigenPodProxyImplementation = new EigenPodProxy(IEigenPodManager(eigenPodManager), slasher);

        beacon = new UpgradeableBeacon(address(eigenPodProxyImplementation));

        pool = PufferPool(payable(address(new PufferPoolMock())));

        // Deploy and initialize EigenPodProxy
        eigenPodProxy = EigenPodProxy(
            payable(
                address(
                    new BeaconProxy(address(beacon), abi.encodeCall(EigenPodProxy.initialize, (IPufferPool(address(pool)))))
                )
            )
        );

        // Replace bytecode of podOwner with Proxy code
        vm.etch(podOwner, address(eigenPodProxy).code);

        bytes32 _BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;
        // Store the right implementation in implementation slot
        vm.store(address(podOwner), _BEACON_SLOT, bytes32(uint256(uint160(address(beacon)))));

        // Set That EigenPod address to be in slot 3 of EigenPodProxy
        address pod = address(eigenPodManager.getPod(podOwner));
        vm.store(address(podOwner), bytes32(uint256(3)), bytes32(uint256(uint160(pod))));

        // Give ETH to pool
        vm.deal(address(pool), 100 ether);

        eigenPodProxy = EigenPodProxy(payable(address(podOwner)));

        // We need to re initialize contract because we've copied the bytecode via vm.etch
        eigenPodProxy.initialize(IPufferPool(address(pool)));

        vm.prank(address(pool));
        eigenPodProxy.setPodProxyOwnerAndRewardsRecipient(alice, alice);

        assertEq(
            address(eigenPodProxy.eigenPod()), address(eigenPodManager.getPod(address(eigenPodProxy))), "puffer pod"
        );

        uint64 timestamp = 0;

        // Set timestamp to 0 (proofs require it)
        vm.warp(timestamp);

        // Simulate `pool.provisionPodETH`
        vm.prank(address(pool));
        eigenPodProxy.callStake{ value: 32 ether }(pubkey, signature, depositDataRoot);

        // Set mock json
        setJSON("./lib/eigenlayer-contracts/src/test/test-data/withdrawalCredentialAndBalanceProof_61336.json");

        // Prepara data for `eigenPodProxy.enableRestaking` call
        bytes32[][] memory validatorFieldsArray = new bytes32[][](1);
        validatorFieldsArray[0] = getValidatorFields();

        BeaconChainProofs.WithdrawalCredentialProofs[] memory proofsArray =
            new BeaconChainProofs.WithdrawalCredentialProofs[](1);
        proofsArray[0] = _getWithdrawalCredentialProof();

        uint40[] memory validatorIndices = new uint40[](1);
        validatorIndices[0] = uint40(getValidatorIndex());

        // Set timestamp (proofs require it)
        vm.warp(timestamp += 1);

        // Eable restaking
        eigenPodProxy.enableRestaking(timestamp, keccak256(pubkey), validatorIndices, proofsArray, validatorFieldsArray);

        // Sanity check copied from EL test
        IStrategy beaconChainETHStrategy = strategyManager.beaconChainETHStrategy();
        uint256 beaconChainETHShares = strategyManager.stakerStrategyShares(podOwner, beaconChainETHStrategy);
        uint256 effectiveBalance =
            uint256(_getEffectiveRestakedBalanceGwei(uint64(REQUIRED_BALANCE_WEI / GWEI_TO_WEI))) * GWEI_TO_WEI;
        require(beaconChainETHShares == effectiveBalance, "strategyManager shares for our pod did not update");

        // Set json to withdrawal proof
        setJSON("./lib/eigenlayer-contracts/src/test/test-data/fullWithdrawalProof.json");
        BeaconChainOracleMock(address(beaconChainOracle)).setBeaconChainStateRoot(getLatestBlockHeaderRoot());

        {
            IEigenPod eigenPod = eigenPodProxy.eigenPod();

            withdrawalFields = getWithdrawalFields();

            uint64 withdrawalAmountGwei =
                Endian.fromLittleEndianUint64(withdrawalFields[BeaconChainProofs.WITHDRAWAL_VALIDATOR_AMOUNT_INDEX]);

            uint64 leftOverBalanceWEI = uint64(
                withdrawalAmountGwei - _getEffectiveRestakedBalanceGwei(eigenPod.MAX_VALIDATOR_BALANCE_GWEI())
            ) * uint64(GWEI_TO_WEI);

            vm.deal(address(eigenPod), leftOverBalanceWEI);

            {
                BeaconChainProofs.WithdrawalProofs[] memory withdrawalProofsArray =
                    new BeaconChainProofs.WithdrawalProofs[](1);
                withdrawalProofsArray[0] = _getWithdrawalProof();
                bytes[] memory validatorFieldsProofArray = new bytes[](1);
                validatorFieldsProofArray[0] = abi.encodePacked(getValidatorProof());
                bytes32[][] memory validatorFieldsArray = new bytes32[][](1);
                validatorFieldsArray[0] = getValidatorFields();
                bytes32[][] memory withdrawalFieldsArray = new bytes32[][](1);
                withdrawalFieldsArray[0] = withdrawalFields;

                // Create delayed withdrawal via EigenPodProxy
                eigenPodProxy.pokePod(
                    IEigenPodProxy.WithdrawalData({
                        withdrawalProofs: withdrawalProofsArray,
                        validatorFieldsProofs: validatorFieldsProofArray,
                        validatorFields: validatorFieldsArray,
                        withdrawalFields: withdrawalFieldsArray,
                        beaconChainETHStrategyIndex: 0,
                        oracleTimestamp: 0
                    })
                );

                // Update block number so that the withdrawal is unlocked
                vm.roll(block.number + WITHDRAWAL_DELAY_BLOCKS + 1);

                uint256 poolBalanceBefore = address(pool).balance;
                uint256 aliceBalanceBefore = alice.balance;

                // Claim withdrawal
                delayedWithdrawalRouter.claimDelayedWithdrawals(podOwner, 1);

                uint256 poolBalanceAfter = address(pool).balance;
                uint256 aliceBalanceAfter = alice.balance;

                // TODO: asserts and calculations and everything correctly
                assertTrue(aliceBalanceAfter > aliceBalanceBefore, "alice did not get eth");
                assertTrue(poolBalanceAfter > poolBalanceBefore, "pool did not get eth");
            }
        }
    }

    /// @notice this function just generates a valid proof so that we can test other functionalities of the withdrawal flow
    function _getWithdrawalProof() internal returns (BeaconChainProofs.WithdrawalProofs memory) {
        IEigenPod newPod = eigenPodManager.getPod(podOwner);

        //make initial deposit
        vm.startPrank(podOwner);
        vm.expectEmit(true, true, true, true, address(newPod));
        emit EigenPodStaked(pubkey);
        eigenPodManager.stake{ value: stakeAmount }(pubkey, signature, depositDataRoot);
        vm.stopPrank();

        {
            bytes32 beaconStateRoot = getBeaconStateRoot();
            bytes32 latestBlockHeaderRoot = getLatestBlockHeaderRoot();
            //set beaconStateRoot
            beaconChainOracle.setBeaconChainStateRoot(latestBlockHeaderRoot);
            bytes32 blockHeaderRoot = getBlockHeaderRoot();
            bytes32 blockBodyRoot = getBlockBodyRoot();
            bytes32 slotRoot = getSlotRoot();
            bytes32 timestampRoot = getTimestampRoot();
            bytes32 executionPayloadRoot = getExecutionPayloadRoot();

            uint256 withdrawalIndex = getWithdrawalIndex();
            uint256 blockHeaderRootIndex = getBlockHeaderRootIndex();

            BeaconChainProofs.WithdrawalProofs memory proofs = BeaconChainProofs.WithdrawalProofs(
                beaconStateRoot,
                abi.encodePacked(getLatestBlockHeaderProof()),
                abi.encodePacked(getBlockHeaderProof()),
                abi.encodePacked(getWithdrawalProof()),
                abi.encodePacked(getSlotProof()),
                abi.encodePacked(getExecutionPayloadProof()),
                abi.encodePacked(getTimestampProof()),
                uint64(blockHeaderRootIndex),
                uint64(withdrawalIndex),
                blockHeaderRoot,
                blockBodyRoot,
                slotRoot,
                timestampRoot,
                executionPayloadRoot
            );
            return proofs;
        }
    }

    function _getEffectiveRestakedBalanceGwei(uint64 amountGwei) internal pure returns (uint64) {
        if (amountGwei < 75e7) {
            return 0;
        }
        //calculates the "floor" of amountGwei - EFFECTIVE_RESTAKED_BALANCE_OFFSET
        uint64 effectiveBalance = uint64((amountGwei - 75e7) / GWEI_TO_WEI * GWEI_TO_WEI);
        return uint64(MathUpgradeable.min(32e9, effectiveBalance));
    }

    function _getWithdrawalCredentialProof() internal returns (BeaconChainProofs.WithdrawalCredentialProofs memory) {
        {
            bytes32 latestBlockHeaderRoot = getLatestBlockHeaderRoot();
            //set beaconStateRoot
            beaconChainOracle.setBeaconChainStateRoot(latestBlockHeaderRoot);

            BeaconChainProofs.WithdrawalCredentialProofs memory proofs = BeaconChainProofs.WithdrawalCredentialProofs(
                getBeaconStateRoot(),
                abi.encodePacked(getLatestBlockHeaderProof()),
                abi.encodePacked(getWithdrawalCredentialProof())
            );
            return proofs;
        }
    }

    function _testDeployAndVerifyNewEigenPod(address _podOwner, bytes memory _signature, bytes32 _depositDataRoot)
        internal
        returns (IEigenPod)
    {
        // (beaconStateRoot, beaconStateMerkleProofForValidators, validatorContainerFields, validatorMerkleProof, validatorTreeRoot, validatorRoot) =
        //     getInitialDepositProof(validatorIndex);

        // bytes32 newBeaconStateRoot = getBeaconStateRoot();
        // BeaconChainOracleMock(address(beaconChainOracle)).setBeaconChainStateRoot(newBeaconStateRoot);

        IEigenPod newPod = eigenPodManager.getPod(_podOwner);

        vm.startPrank(_podOwner);
        vm.expectEmit(true, true, true, true, address(newPod));
        emit EigenPodStaked(pubkey);
        eigenPodManager.stake{ value: stakeAmount }(pubkey, _signature, _depositDataRoot);
        vm.stopPrank();

        uint64 timestamp = 0;
        // vm.expectEmit(true, true, true, true, address(newPod));
        // emit ValidatorRestaked(validatorIndex);

        bytes32[][] memory validatorFieldsArray = new bytes32[][](1);
        validatorFieldsArray[0] = getValidatorFields();

        BeaconChainProofs.WithdrawalCredentialProofs[] memory proofsArray =
            new BeaconChainProofs.WithdrawalCredentialProofs[](1);
        proofsArray[0] = _getWithdrawalCredentialProof();

        uint40[] memory validatorIndices = new uint40[](1);
        validatorIndices[0] = uint40(getValidatorIndex());

        vm.startPrank(_podOwner);
        vm.warp(timestamp);
        newPod.activateRestaking();
        emit log_named_bytes32(
            "restaking activated", BeaconChainOracleMock(address(beaconChainOracle)).mockBeaconChainStateRoot()
        );
        vm.warp(timestamp += 1);
        newPod.verifyWithdrawalCredentials(timestamp, validatorIndices, proofsArray, validatorFieldsArray);
        IStrategy beaconChainETHStrategy = strategyManager.beaconChainETHStrategy();
        vm.stopPrank();

        uint256 beaconChainETHShares = strategyManager.stakerStrategyShares(_podOwner, beaconChainETHStrategy);
        uint256 effectiveBalance =
            uint256(_getEffectiveRestakedBalanceGwei(uint64(REQUIRED_BALANCE_WEI / GWEI_TO_WEI))) * GWEI_TO_WEI;
        require(beaconChainETHShares == effectiveBalance, "strategyManager shares not updated correctly");
        return newPod;
    }
}
