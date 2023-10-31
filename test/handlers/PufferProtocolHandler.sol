// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { EnumerableMap } from "openzeppelin/utils/structs/EnumerableMap.sol";
import { EnumerableSet } from "openzeppelin/utils/structs/EnumerableSet.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { console } from "forge-std/console.sol";
import { Test } from "forge-std/Test.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { Status } from "puffer/struct/Status.sol";
import { TestHelper } from "../helpers/TestHelper.sol";

contract PufferProtocolHandler is Test {
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using EnumerableSet for EnumerableSet.AddressSet;

    TestHelper testhelper;

    event ValidatorKeyRegistered(bytes indexed pubKey, uint256 indexed, bytes32 indexed);

    address DAO = makeAddr("DAO");

    uint256[] guardiansEnclavePks;
    PufferPool pool;
    IWithdrawalPool withdrawalPool;
    PufferProtocol pufferProtocol;

    EnumerableMap.AddressToUintMap _pufETHDepositors;

    EnumerableSet.AddressSet _nodeOperators;

    struct Data {
        Safe owner;
        bytes32 pubKeyPart;
    }

    uint256 public ghost_eth_deposited_amount;
    uint256 public ghost_locked_amount;
    uint256 public ghost_eth_rewards_amount;
    uint256 public ghost_block_number = 1;

    // Previous ETH balance of PufferPool
    uint256 public previousBalance;

    // This is important because that is the only way that ETH is leaving PufferPool
    bool public ethLeavingThePool;

    // Counter for the calls in the invariant test
    mapping(bytes32 => uint256) public calls;

    struct ProvisioningData {
        Status status;
        bytes32 pubKeypart;
    }

    mapping(bytes32 queue => ProvisioningData[] validators) _validatorQueue;
    mapping(bytes32 queue => uint256 nextForProvisioning) ghost_nextForProvisioning;

    modifier assumeEOA(address addr) {
        console.log(addr.code.length, "code len");
        console.logBytes32(addr.codehash);
        console.log("codehash");
        vm.assume(addr != address(0));
        vm.assume(addr != address(1));
        vm.assume(addr != address(2));
        vm.assume(addr != address(3));
        vm.assume(addr != address(4));
        vm.assume(addr != address(5));
        vm.assume(addr != address(6));
        vm.assume(addr != address(7));
        vm.assume(addr != address(8));
        vm.assume(addr != address(9));
        vm.assume(addr.code.length == 0);
        vm.assume(addr.codehash == bytes32(0));
        _;
    }

    constructor(
        TestHelper helper,
        PufferPool _pool,
        IWithdrawalPool _withdrawalPool,
        PufferProtocol protocol,
        uint256[] memory _guardiansEnclavePks
    ) {
        testhelper = helper;
        pufferProtocol = protocol;
        pool = _pool;
        withdrawalPool = _withdrawalPool;
        guardiansEnclavePks.push(_guardiansEnclavePks[0]);
        guardiansEnclavePks.push(_guardiansEnclavePks[1]);
        guardiansEnclavePks.push(_guardiansEnclavePks[2]);

        vm.deal(address(this), 200 ether);

        uint256 initialDepositAmount = 200 ether;
        // bootstrap pool with some eth, assume this will never be liquidated
        pool.depositETH{ value: initialDepositAmount }();

        ghost_eth_deposited_amount += initialDepositAmount;
    }

    // https://github.com/foundry-rs/foundry/issues/5795
    modifier setCorrectBlockNumber() {
        vm.roll(ghost_block_number);
        _;
    }

    modifier recordPreviousBalance() {
        previousBalance = address(pool).balance;
        _;
    }

    modifier isETHLeavingThePool() {
        if (msg.sig == this.provisionNode.selector) {
            ethLeavingThePool = true;
        } else {
            ethLeavingThePool = false;
        }
        _;
    }

    modifier countCall(bytes32 key) {
        calls[key]++;
        _;
    }

    // Simulates pool getting ETH as a reward / donation
    function depositStakingRewards(uint256 stakingRewardsAmount)
        public
        setCorrectBlockNumber
        recordPreviousBalance
        isETHLeavingThePool
        countCall("depositStakingRewards")
    {
        // bound the result between min deposit amount and uint64.max value ~18.44 ETH
        stakingRewardsAmount = bound(stakingRewardsAmount, 0.01 ether, uint256(type(uint64).max));

        vm.deal(address(this), stakingRewardsAmount);
        vm.startPrank(address(this));
        pool.depositRewards{ value: stakingRewardsAmount }();
        vm.stopPrank();

        ghost_eth_rewards_amount += stakingRewardsAmount;
    }

    // Posts proof of reserve
    function proofOfReserve()
        public
        setCorrectBlockNumber
        recordPreviousBalance
        isETHLeavingThePool
        countCall("proofOfReserve")
    {
        // advance block to where it can be updated next
        uint256 nextUpdate = block.number + 7149; // Update interval is 7141 `_UPDATE_INTERVAL` on pufferProtocol
        ghost_block_number = nextUpdate;
        vm.roll(nextUpdate);

        uint256 pufETHSupply = pool.totalSupply();

        // At the moment there is no ETH landing in our strategies, instead we simulate the deposit to pufferPool using `depositStakingRewards`
        uint256 ethAmount = address(pool).balance + address(withdrawalPool).balance + ghost_eth_rewards_amount;
        uint256 lockedETH = ghost_locked_amount;

        vm.startPrank(address(testhelper.guardiansSafe()));
        pufferProtocol.proofOfReserve({
            ethAmount: ethAmount,
            lockedETH: lockedETH,
            pufETHTotalSupply: pufETHSupply,
            blockNumber: block.number - 10
        });
        vm.stopPrank();
    }

    // User deposits ETH to get pufETH
    function depositETH(address depositor, uint256 amount)
        public
        setCorrectBlockNumber
        assumeEOA(depositor)
        recordPreviousBalance
        isETHLeavingThePool
        countCall("depositETH")
    {
        // bound the result between min deposit amount and uint64.max value ~18.44 ETH
        amount = bound(amount, 0.01 ether, uint256(type(uint64).max));
        vm.deal(depositor, amount);

        uint256 expectedPufETHAmount = pool.calculateETHToPufETHAmount(amount);

        uint256 prevBalance = pool.balanceOf(depositor);

        vm.startPrank(depositor);
        uint256 pufETHAmount = pool.depositETH{ value: amount }();
        vm.stopPrank();

        uint256 afterBalance = pool.balanceOf(depositor);

        ghost_eth_deposited_amount += amount;

        require(expectedPufETHAmount == afterBalance - prevBalance, "pufETH calculation is wrong");
        require(pufETHAmount == expectedPufETHAmount, "amounts dont match");

        // Store the depositor and amount of pufETH
        (, uint256 prevAmount) = _pufETHDepositors.tryGet(depositor);
        _pufETHDepositors.set(depositor, prevAmount + expectedPufETHAmount);
    }

    // withdraw pufETH for ETH
    function withdrawETH(uint256 withdrawerSeed, address depositor, uint256 depositAmount)
        public
        setCorrectBlockNumber
        assumeEOA(depositor)
        recordPreviousBalance
        isETHLeavingThePool
        countCall("withdrawETH")
    {
        // If there are no pufETH holders, deposit ETH
        if (_pufETHDepositors.length() == 0) {
            return depositETH(depositor, depositAmount);
        }

        uint256 withdrawerIndex = withdrawerSeed % _pufETHDepositors.length();

        (address withdrawer, uint256 amount) = _pufETHDepositors.at(withdrawerIndex);

        // Due to limited liquidity in WithdrawalPool, we are withdrawing 1/3 of the user's balance at a time
        uint256 burnAmount = amount / 3;

        console.log("WITHDRAWAL POOL BALANCE:", address(withdrawalPool).balance);

        vm.startPrank(withdrawer);
        pool.approve(address(withdrawalPool), type(uint256).max);
        withdrawalPool.withdrawETH(withdrawer, amount);
        vm.stopPrank();

        _pufETHDepositors.set(withdrawer, amount - burnAmount);
    }

    // Registers Validator key
    function registerValidatorKey(address nodeOperator, bytes32 pubKeyPart, uint256 strategySelectorSeed)
        public
        setCorrectBlockNumber
        assumeEOA(nodeOperator)
        recordPreviousBalance
        isETHLeavingThePool
        countCall("registerValidatorKey")
    {
        bytes32[] memory strategyWeights = pufferProtocol.getStrategyWeights();
        uint256 strategyIndex = strategySelectorSeed % strategyWeights.length;

        bytes32 startegyName = strategyWeights[strategyIndex];

        vm.deal(nodeOperator, 5 ether);
        vm.startPrank(nodeOperator);

        uint256 depositedETHAmount = _registerValidatorKey(pubKeyPart, startegyName);

        // Store data and push to queue
        ProvisioningData memory validator;
        validator.status = Status.PENDING;
        validator.pubKeypart = pubKeyPart;

        _validatorQueue[startegyName].push(validator);

        vm.stopPrank();

        // Account for that deposited eth in ghost variable
        ghost_eth_deposited_amount += depositedETHAmount;

        // Add node operator to the set
        _nodeOperators.add(nodeOperator);
    }

    // Creates a puffer strategy and adds it to weights
    function createPufferStrategy(bytes32 startegyName)
        public
        setCorrectBlockNumber
        recordPreviousBalance
        isETHLeavingThePool
        countCall("createPufferStrategy")
    {
        vm.startPrank(DAO);

        bytes32[] memory weights = pufferProtocol.getStrategyWeights();

        bytes32[] memory newWeights = new bytes32[](weights.length + 1 );
        for (uint256 i = 0; i < weights.length; ++i) {
            newWeights[i] = weights[i];
        }

        try pufferProtocol.createPufferStrategy(startegyName) {
            newWeights[weights.length] = startegyName;
            pufferProtocol.setStrategyWeights(newWeights);
        } catch (bytes memory reason) { }

        vm.stopPrank();
    }

    // Starts the validating process
    function provisionNode(address nodeOperator, bytes32 pubKeyPart, uint256 strategySelectorSeed)
        public
        setCorrectBlockNumber
        recordPreviousBalance
        isETHLeavingThePool
        countCall("provisionNode")
    {
        // If we don't have proxies, create and register validator key, then call this function again with the same params
        if (_nodeOperators.length() == 0) {
            registerValidatorKey(nodeOperator, pubKeyPart, strategySelectorSeed);
            return provisionNode(nodeOperator, pubKeyPart, strategySelectorSeed);
        }

        // If there is nothing to be provisioned, index returned is max uint256
        (, uint256 i) = pufferProtocol.getNextValidatorToProvision();
        if (i == type(uint256).max) {
            ethLeavingThePool = false;
            return;
        }

        uint256 startegySelectIndex = pufferProtocol.getStrategySelectIndex();
        bytes32[] memory weights = pufferProtocol.getStrategyWeights();

        bytes32 strategyName = weights[startegySelectIndex % weights.length];

        uint256 nextIdx = ghost_nextForProvisioning[strategyName];

        // Nothing to provision
        if (_validatorQueue[strategyName].length <= nextIdx) {
            ethLeavingThePool = false;
            return;
        }

        ProvisioningData memory validatorData = _validatorQueue[strategyName][nextIdx];

        if (validatorData.status == Status.PENDING) {
            bytes memory sig = _getPubKey(validatorData.pubKeypart);

            bytes[] memory signatures = _getGuardianSignatures(sig);
            pufferProtocol.provisionNode(signatures);

            // Update ghost variables
            ghost_locked_amount += 32 ether;
            ghost_nextForProvisioning[strategyName]++;
        }
    }

    // Stops the validator registration process
    // function stopRegistration(uint256 eigenPodProxySeed, address podAccountOwner, bytes32 pubKeyPart)
    //     public
    //     isETHLeavingThePool
    //     countCall("stopRegistration")
    //     recordPreviousBalance
    // {
    //     // If we don't have proxies, create and register validator key, then call this function again with the same params
    //     if (_eigenPodProxies.length() == 0) {
    //         return registerValidatorKey(podAccountOwner, pubKeyPart);
    //     }

    //     uint256 eigePodProxyIndex = eigenPodProxySeed % _eigenPodProxies.length();

    //     // Fetch EigenPodProxy from the set
    //     IEigenPodProxy proxy = IEigenPodProxy(_eigenPodProxies.at(eigePodProxyIndex));

    //     Data memory data = _eigenPodProxiesData[address(proxy)];

    //     bytes memory pubKey = _getPubKey(data.pubKeyPart);

    //     vm.startPrank(address(data.owner));
    //     proxy.stopRegistration(keccak256(pubKey));
    //     vm.stopPrank();
    // }

    function callSummary() external view {
        console.log("Call summary:");
        console.log("-------------------");
        console.log("depositStakingRewards", calls["depositStakingRewards"]);
        console.log("depositETH", calls["depositETH"]);
        console.log("withdrawETH", calls["withdrawETH"]);
        console.log("registerValidatorKey", calls["registerValidatorKey"]);
        console.log("createPufferStrategy", calls["createPufferStrategy"]);
        console.log("provisionNode", calls["provisionNode"]);
        console.log("proofOfReserve", calls["proofOfReserve"]);
        console.log("-------------------");
    }

    function _getMockValidatorKeyData(bytes memory pubKey, bytes32 strategyName)
        internal
        view
        returns (ValidatorKeyData memory)
    {
        bytes[] memory newSetOfPubKeys = new bytes[](3);

        // we have 3 guardians in TestHelper.sol
        newSetOfPubKeys[0] = bytes("key1");
        newSetOfPubKeys[0] = bytes("key2");
        newSetOfPubKeys[0] = bytes("key3");

        address strategy = pufferProtocol.getStrategyAddress(strategyName);

        bytes memory withdrawalCredentials = pufferProtocol.getWithdrawalCredentials(strategy);

        bytes memory randomSignature =
            hex"8aa088146c8c6ca6d8ad96648f20e791be7c449ce7035a6bd0a136b8c7b7867f730428af8d4a2b69658bfdade185d6110b938d7a59e98d905e922d53432e216dc88c3384157d74200d3f2de51d31737ce19098ff4d4f54f77f0175e23ac98da5";

        ValidatorKeyData memory validatorData = ValidatorKeyData({
            blsPubKey: pubKey, // key length must be 48 byte
            // mock signature copied from some random deposit transaction
            signature: randomSignature,
            depositDataRoot: pufferProtocol.getDepositDataRoot({
                pubKey: pubKey,
                signature: randomSignature,
                withdrawalCredentials: withdrawalCredentials
            }),
            blsEncryptedPrivKeyShares: new bytes[](3),
            blsPubKeySet: new bytes(48),
            raveEvidence: new bytes(1) // Guardians are checking it off chain
         });

        return validatorData;
    }

    function _getPubKey(bytes32 pubKeypart) internal pure returns (bytes memory) {
        return bytes.concat(abi.encodePacked(pubKeypart), bytes16(""));
    }

    // Copied from PufferProtocol.t.sol
    function _registerValidatorKey(bytes32 pubKeyPart, bytes32 strategyName)
        internal
        returns (uint256 depositedETHAmount)
    {
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(1);

        bytes memory pubKey = _getPubKey(pubKeyPart);

        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, strategyName);

        uint256 idx = pufferProtocol.getPendingValidatorIndex(strategyName);

        uint256 bond = 1 ether;

        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRegistered(pubKey, idx, strategyName);
        pufferProtocol.registerValidatorKey{ value: (smoothingCommitment + bond) }(validatorKeyData, strategyName, 1);

        return (smoothingCommitment + bond);
    }

    // Copied from PufferProtocol.t.sol
    function _getGuardianSignatures(bytes memory pubKey) internal view returns (bytes[] memory) {
        (bytes32 strategyName, uint256 pendingIdx) = pufferProtocol.getNextValidatorToProvision();
        Validator memory validator = pufferProtocol.getValidatorInfo(strategyName, pendingIdx);
        // If there is no strategy return empty byte array
        if (validator.strategy == address(0)) {
            return new bytes[](0);
        }
        bytes memory withdrawalCredentials = pufferProtocol.getWithdrawalCredentials(validator.strategy);

        bytes32 digest = (pufferProtocol.getGuardianModule()).getMessageToBeSigned(
            pubKey,
            validator.signature,
            withdrawalCredentials,
            pufferProtocol.getDepositDataRoot({
                pubKey: pubKey,
                signature: validator.signature,
                withdrawalCredentials: withdrawalCredentials
            })
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(testhelper.guardian1SKEnclave(), digest);
        bytes memory signature1 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        (v, r, s) = vm.sign(testhelper.guardian2SKEnclave(), digest);
        (v, r, s) = vm.sign(testhelper.guardian3SKEnclave(), digest);
        bytes memory signature2 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        (v, r, s) = vm.sign(testhelper.guardian3SKEnclave(), digest);
        bytes memory signature3 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        bytes[] memory guardianSignatures = new bytes[](3);
        guardianSignatures[0] = signature1;
        guardianSignatures[1] = signature2;
        guardianSignatures[2] = signature3;

        return guardianSignatures;
    }
}
