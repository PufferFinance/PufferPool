// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { EnumerableMap } from "openzeppelin/utils/structs/EnumerableMap.sol";
import { EnumerableSet } from "openzeppelin/utils/structs/EnumerableSet.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { console } from "forge-std/console.sol";
import { Test } from "forge-std/Test.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { Status } from "puffer/struct/Status.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { LibGuardianMessages } from "puffer/LibGuardianMessages.sol";

contract PufferProtocolHandler is Test {
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using EnumerableSet for EnumerableSet.AddressSet;
    using SafeTransferLib for address;
    using SafeTransferLib for address payable;

    uint256 guardian1SKEnclave = 81165043675487275545095207072241430673874640255053335052777448899322561824201;
    address guardian1Enclave = vm.addr(guardian1SKEnclave);
    uint256 guardian2SKEnclave = 90480947395980135991870782913815514305328820213706480966227475230529794843518;
    address guardian2Enclave = vm.addr(guardian2SKEnclave);
    uint256 guardian3SKEnclave = 56094429399408807348734910221877888701411489680816282162734349635927251229227;
    TestHelper testhelper;

    address[] public actors;

    address DAO = makeAddr("DAO");

    uint256[] guardiansEnclavePks;
    PufferPool pool;
    IWithdrawalPool withdrawalPool;
    PufferProtocol pufferProtocol;

    EnumerableMap.AddressToUintMap _pufETHDepositors;

    EnumerableSet.AddressSet _nodeOperators;

    struct Data {
        address owner;
        bytes32 pubKeyPart;
    }

    uint256 public ghost_eth_deposited_amount;
    uint256 public ghost_locked_amount;
    uint256 public ghost_eth_rewards_amount;
    uint256 public ghost_block_number = 10000;
    uint256 public ghost_validators = 0;
    uint256 public ghost_pufETH_bond_amount = 0; // bond amount that should be in puffer protocol

    // Previous ETH balance of PufferPool
    uint256 public previousBalance;

    // This is important because that is the only way that ETH is leaving PufferPool
    bool public ethLeavingThePool;

    // Counter for the calls in the invariant test
    mapping(bytes32 => uint256) public calls;
    uint256 totalCalls;

    struct ProvisioningData {
        Status status;
        bytes32 pubKeypart;
    }

    mapping(bytes32 queue => ProvisioningData[] validators) _validatorQueue;
    mapping(bytes32 queue => uint256 nextForProvisioning) ghost_nextForProvisioning;

    address internal currentActor;

    constructor(
        TestHelper helper,
        PufferPool _pool,
        IWithdrawalPool _withdrawalPool,
        PufferProtocol protocol,
        uint256[] memory _guardiansEnclavePks
    ) {
        // Initialize actors, skip precompiles
        for (uint256 i = 11; i < 1000; ++i) {
            address actor = address(uint160(i));
            if (actor.code.length != 0) {
                continue;
            }
            vm.deal(actor, 1000 ether);

            actors.push(actor);
        }

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

    modifier useActor(uint256 actorIndexSeed) {
        currentActor = actors[bound(actorIndexSeed, 0, actors.length - 1)];
        vm.startPrank(currentActor);
        _;
        vm.stopPrank();
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
        totalCalls++;
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
        stakingRewardsAmount = bound(stakingRewardsAmount, 1, uint256(type(uint64).max));

        vm.deal(address(this), stakingRewardsAmount);
        vm.startPrank(address(this));
        address(pool).safeTransferETH(stakingRewardsAmount);
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
        uint256 blockNumber = block.number;
        uint256 activeValidators = 20000;
        // advance block to where it can be updated next
        uint256 nextUpdate = block.number + 7149; // Update interval is 7141 `_UPDATE_INTERVAL` on pufferProtocol
        ghost_block_number = nextUpdate;
        vm.roll(nextUpdate);

        uint256 pufETHSupply = pool.totalSupply();

        // At the moment there is no ETH landing in our modules, instead we simulate the deposit to pufferPool using `depositStakingRewards`
        uint256 ethAmount = address(pool).balance + address(withdrawalPool).balance + ghost_eth_rewards_amount;
        uint256 lockedETH = ghost_locked_amount;

        bytes32 signedMessageHash = LibGuardianMessages.getProofOfReserveMessage(
            ethAmount, lockedETH, pufETHSupply, blockNumber, activeValidators
        );

        pufferProtocol.proofOfReserve({
            ethAmount: ethAmount,
            lockedETH: lockedETH,
            pufETHTotalSupply: pufETHSupply,
            blockNumber: blockNumber,
            numberOfActiveValidators: activeValidators,
            guardianSignatures: _getGuardianEOASignatures(signedMessageHash)
        });
        vm.stopPrank();
    }

    // User deposits ETH to get pufETH
    function depositETH(uint256 depositorSeed, uint256 amount)
        public
        useActor(depositorSeed)
        setCorrectBlockNumber
        recordPreviousBalance
        isETHLeavingThePool
        countCall("depositETH")
    {
        // bound the result between min deposit amount and uint64.max value ~18.44 ETH
        amount = bound(amount, 0.01 ether, uint256(type(uint64).max));
        vm.deal(currentActor, amount);

        uint256 expectedPufETHAmount = pool.calculateETHToPufETHAmount(amount);

        uint256 prevBalance = pool.balanceOf(currentActor);

        uint256 pufETHAmount = pool.depositETH{ value: amount }();

        uint256 afterBalance = pool.balanceOf(currentActor);

        ghost_eth_deposited_amount += amount;

        require(expectedPufETHAmount == afterBalance - prevBalance, "pufETH calculation is wrong");
        require(pufETHAmount == expectedPufETHAmount, "amounts dont match");

        // Store the depositor and amount of pufETH
        (, uint256 prevAmount) = _pufETHDepositors.tryGet(currentActor);
        _pufETHDepositors.set(currentActor, prevAmount + expectedPufETHAmount);
    }

    // withdraw pufETH for ETH
    function withdrawETH(uint256 withdrawerSeed)
        public
        setCorrectBlockNumber
        recordPreviousBalance
        isETHLeavingThePool
        countCall("withdrawETH")
    {
        // If there are no pufETH holders, deposit ETH
        if (_pufETHDepositors.length() == 0) {
            return;
        }

        uint256 withdrawerIndex = withdrawerSeed % _pufETHDepositors.length();

        (address withdrawer, uint256 amount) = _pufETHDepositors.at(withdrawerIndex);

        console.log("Withdrawer pufETH amount", amount);

        // Due to limited liquidity in WithdrawalPool, we are withdrawing 1/3 of the user's balance at a time
        uint256 burnAmount = amount / 3;
        _pufETHDepositors.set(withdrawer, (amount - burnAmount));

        vm.deal(address(withdrawalPool), 1000000 ether);
        console.log("WITHDRAWAL POOL BALANCE:", address(withdrawalPool).balance);

        vm.startPrank(withdrawer);
        pool.approve(address(withdrawalPool), type(uint256).max);
        withdrawalPool.withdrawETH(withdrawer, burnAmount);
        vm.stopPrank();
    }

    // We have three of these to get better call distribution in the invariant tests
    function registerValidatorKey3(uint256 nodeOperatorSeed, bytes32 pubKeyPart, uint256 moduleSelectorSeed)
        public
        setCorrectBlockNumber
        useActor(nodeOperatorSeed)
        recordPreviousBalance
        isETHLeavingThePool
        countCall("registerValidatorKey")
    {
        _registerValidatorKey(pubKeyPart, moduleSelectorSeed);
    }

    function registerValidatorKey2(uint256 nodeOperatorSeed, bytes32 pubKeyPart, uint256 moduleSelectorSeed)
        public
        setCorrectBlockNumber
        useActor(nodeOperatorSeed)
        recordPreviousBalance
        isETHLeavingThePool
        countCall("registerValidatorKey")
    {
        _registerValidatorKey(pubKeyPart, moduleSelectorSeed);
    }

    // Registers Validator key
    function registerValidatorKey(uint256 nodeOperatorSeed, bytes32 pubKeyPart, uint256 moduleSelectorSeed)
        public
        setCorrectBlockNumber
        useActor(nodeOperatorSeed)
        recordPreviousBalance
        isETHLeavingThePool
        countCall("registerValidatorKey")
    {
        _registerValidatorKey(pubKeyPart, moduleSelectorSeed);
    }

    function _registerValidatorKey(bytes32 pubKeyPart, uint256 moduleSelectorSeed) internal {
        bytes32[] memory moduleWeights = pufferProtocol.getModuleWeights();
        uint256 moduleIndex = moduleSelectorSeed % moduleWeights.length;

        bytes32 moduleName = moduleWeights[moduleIndex];

        vm.deal(currentActor, 5 ether);

        pufferProtocol.getPendingValidatorIndex(moduleName);

        uint256 depositedETHAmount = _registerValidatorKey(pubKeyPart, moduleName);

        // Store data and push to queue
        ProvisioningData memory validator;
        validator.status = Status.PENDING;
        validator.pubKeypart = pubKeyPart;

        _validatorQueue[moduleName].push(validator);

        vm.stopPrank();

        // Account for that deposited eth in ghost variable
        ghost_eth_deposited_amount += depositedETHAmount;
        ghost_validators += 1;
        ghost_pufETH_bond_amount += pool.calculateETHToPufETHAmount(1 ether);

        // Add node operator to the set
        _nodeOperators.add(currentActor);
    }

    // Creates a puffer module and adds it to weights
    function createPufferModule(bytes32 startegyName)
        public
        setCorrectBlockNumber
        recordPreviousBalance
        isETHLeavingThePool
        countCall("createPufferModule")
    {
        vm.startPrank(DAO);

        bytes32[] memory weights = pufferProtocol.getModuleWeights();

        bytes32[] memory newWeights = new bytes32[](weights.length + 1 );
        for (uint256 i = 0; i < weights.length; ++i) {
            newWeights[i] = weights[i];
        }

        try pufferProtocol.createPufferModule(startegyName) {
            newWeights[weights.length] = startegyName;
            pufferProtocol.setModuleWeights(newWeights);
        } catch (bytes memory reason) { }

        vm.stopPrank();
    }

    // Starts the validating process
    function provisionNode()
        public
        setCorrectBlockNumber
        recordPreviousBalance
        isETHLeavingThePool
        countCall("provisionNode")
    {
        // If we don't have proxies, create and register validator key, then call this function again with the same params
        if (_nodeOperators.length() == 0) {
            ethLeavingThePool = false;
            return;
        }

        // If there is nothing to be provisioned, index returned is max uint256
        (, uint256 i) = pufferProtocol.getNextValidatorToProvision();
        if (i == type(uint256).max) {
            ethLeavingThePool = false;
            return;
        }

        uint256 moduleSelectIndex = pufferProtocol.getModuleSelectIndex();
        bytes32[] memory weights = pufferProtocol.getModuleWeights();

        bytes32 moduleName = weights[moduleSelectIndex % weights.length];

        uint256 nextIdx = ghost_nextForProvisioning[moduleName];

        // Nothing to provision
        if (_validatorQueue[moduleName].length <= nextIdx) {
            ethLeavingThePool = false;
            return;
        }

        ProvisioningData memory validatorData = _validatorQueue[moduleName][nextIdx];

        if (validatorData.status == Status.PENDING) {
            bytes memory sig = _getPubKey(validatorData.pubKeypart);

            bytes[] memory signatures = _getGuardianSignatures(sig);
            pufferProtocol.provisionNode(signatures);

            // Update ghost variables
            ghost_locked_amount += 32 ether;
            ghost_nextForProvisioning[moduleName]++;
        }
    }

    // Stops the validator registration process
    function stopRegistration(uint256 moduleSelectIndex)
        public
        setCorrectBlockNumber
        isETHLeavingThePool
        recordPreviousBalance
        countCall("stopRegistration")
    {
        bytes32[] memory weights = pufferProtocol.getModuleWeights();
        bytes32 moduleName = weights[moduleSelectIndex % weights.length];
        uint256 pendingIdx = pufferProtocol.getPendingValidatorIndex(moduleName);

        if (pendingIdx == 0) {
            return;
        }
        // Set skip index to pending index for that module
        uint256 skipIdx = pendingIdx - 1;

        Validator memory info = pufferProtocol.getValidatorInfo(moduleName, skipIdx);
        if (info.status == Status.PENDING) {
            // Accounting in ghost vars
            ghost_pufETH_bond_amount -= info.bond;
            ghost_validators -= 1;

            uint256 pufETHBalanceBefore = pool.balanceOf(info.node);
            vm.startPrank(info.node);
            pufferProtocol.stopRegistration(moduleName, skipIdx);
            uint256 pufETHBalanceAfter = pool.balanceOf(info.node);
            assertGt(pufETHBalanceAfter, pufETHBalanceBefore);
            _validatorQueue[moduleName][skipIdx].status = Status.DEQUEUED;
            console.log("=== Stopped the registration ===");
        }
    }

    function callSummary() external view {
        console.log("Call summary:");
        console.log("-------------------");
        console.log("totalCalls", totalCalls);
        console.log("depositStakingRewards", calls["depositStakingRewards"]);
        console.log("depositETH", calls["depositETH"]);
        console.log("withdrawETH", calls["withdrawETH"]);
        console.log("registerValidatorKey", calls["registerValidatorKey"]);
        console.log("createPufferModule", calls["createPufferModule"]);
        console.log("provisionNode", calls["provisionNode"]);
        console.log("proofOfReserve", calls["proofOfReserve"]);
        console.log("stopRegistration", calls["stopRegistration"]);
        console.log("-------------------");
    }

    function _getMockValidatorKeyData(bytes memory pubKey, bytes32 moduleName)
        internal
        view
        returns (ValidatorKeyData memory)
    {
        bytes[] memory newSetOfPubKeys = new bytes[](3);

        // we have 3 guardians in TestHelper.sol
        newSetOfPubKeys[0] = bytes("key1");
        newSetOfPubKeys[0] = bytes("key2");
        newSetOfPubKeys[0] = bytes("key3");

        address module = pufferProtocol.getModuleAddress(moduleName);

        bytes memory withdrawalCredentials = pufferProtocol.getWithdrawalCredentials(module);

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
    function _registerValidatorKey(bytes32 pubKeyPart, bytes32 moduleName)
        internal
        returns (uint256 depositedETHAmount)
    {
        uint256 momths = bound(block.timestamp, 0, 12);
        uint256 smoothingCommitment = pufferProtocol.getSmoothingCommitment(momths);

        bytes memory pubKey = _getPubKey(pubKeyPart);

        ValidatorKeyData memory validatorKeyData = _getMockValidatorKeyData(pubKey, moduleName);

        uint256 idx = pufferProtocol.getPendingValidatorIndex(moduleName);

        uint256 bond = 1 ether;

        vm.expectEmit(true, true, true, true);
        emit IPufferProtocol.ValidatorKeyRegistered(pubKey, idx, moduleName, true);
        pufferProtocol.registerValidatorKey{ value: (smoothingCommitment + bond) }(validatorKeyData, moduleName, momths);

        return (smoothingCommitment + bond);
    }

    // Copied from PufferProtocol.t.sol
    function _getGuardianSignatures(bytes memory pubKey) internal view returns (bytes[] memory) {
        (bytes32 moduleName, uint256 pendingIdx) = pufferProtocol.getNextValidatorToProvision();
        Validator memory validator = pufferProtocol.getValidatorInfo(moduleName, pendingIdx);
        // If there is no module return empty byte array
        if (validator.module == address(0)) {
            return new bytes[](0);
        }
        bytes memory withdrawalCredentials = pufferProtocol.getWithdrawalCredentials(validator.module);

        bytes32 digest = LibGuardianMessages.getMessageToBeSigned(
            pubKey,
            validator.signature,
            withdrawalCredentials,
            pufferProtocol.getDepositDataRoot({
                pubKey: pubKey,
                signature: validator.signature,
                withdrawalCredentials: withdrawalCredentials
            })
        );

        return _getGuardianEnclaveSignatures(digest);
    }

    function _getGuardianEnclaveSignatures(bytes32 digest) internal view returns (bytes[] memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardian1SKEnclave, digest);
        bytes memory signature1 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        (v, r, s) = vm.sign(guardian2SKEnclave, digest);
        bytes memory signature2 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        (v, r, s) = vm.sign(guardian3SKEnclave, digest);
        bytes memory signature3 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        bytes[] memory guardianSignatures = new bytes[](3);
        guardianSignatures[0] = signature1;
        guardianSignatures[1] = signature2;
        guardianSignatures[2] = signature3;

        return guardianSignatures;
    }

    function _getGuardianEOASignatures(bytes32 digest) internal returns (bytes[] memory) {
        // Create Guardian wallets
        (, uint256 guardian1SK) = makeAddrAndKey("guardian1");
        (, uint256 guardian2SK) = makeAddrAndKey("guardian2");
        (, uint256 guardian3SK) = makeAddrAndKey("guardian3");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardian1SK, digest);
        bytes memory signature1 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        (v, r, s) = vm.sign(guardian2SK, digest);
        bytes memory signature2 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        (v, r, s) = vm.sign(guardian3SK, digest);
        bytes memory signature3 = abi.encodePacked(r, s, v); // note the order here is different from line above.

        bytes[] memory guardianSignatures = new bytes[](3);
        guardianSignatures[0] = signature1;
        guardianSignatures[1] = signature2;
        guardianSignatures[2] = signature3;

        return guardianSignatures;
    }
}
