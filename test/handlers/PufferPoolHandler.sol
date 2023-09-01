// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { EnumerableMap } from "openzeppelin/utils/structs/EnumerableMap.sol";
import { EnumerableSet } from "openzeppelin/utils/structs/EnumerableSet.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { RaveEvidence } from "puffer/interface/RaveEvidence.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { console } from "forge-std/console.sol";
import { TestBase } from "../TestBase.t.sol";

contract PufferPoolHandler is TestBase {
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using EnumerableSet for EnumerableSet.AddressSet;

    uint256[] guardiansEnclavePks;
    PufferPool pool;
    WithdrawalPool withdrawalPool;

    EnumerableMap.AddressToUintMap _pufETHDepositors;

    EnumerableSet.AddressSet _podAccountOwners;

    EnumerableSet.AddressSet _eigenPodProxies;

    struct Data {
        Safe owner;
        bytes32 pubKeyPart;
    }

    // EigenPodProxy => Data about that eigne pod proxy
    mapping(address => Data) _eigenPodProxiesData;

    uint256 public ghost_eth_deposited_amount;
    uint256 public ghost_eth_rewards_amount;

    address[] private _guardians;

    // Previous ETH balance of PufferPool
    uint256 public previousBalance;

    // This is important because that is the only way that ETH is leaving PufferPool
    bool public ethLeavingThePool;

    // Counter for the calls in the invariant test
    mapping(bytes32 => uint256) public calls;

    constructor(PufferPool _pool, WithdrawalPool _withdrawalPool, uint256[] memory _guardiansEnclavePks) {
        pool = _pool;
        withdrawalPool = _withdrawalPool;
        guardiansEnclavePks.push(_guardiansEnclavePks[0]);
        guardiansEnclavePks.push(_guardiansEnclavePks[1]);
        guardiansEnclavePks.push(_guardiansEnclavePks[2]);

        _skipDefaultFuzzAddresses();
        fuzzedAddressMapping[address(pool)] = true;
        fuzzedAddressMapping[address(_withdrawalPool)] = true;
    }

    modifier recordPreviousBalance() {
        previousBalance = address(pool).balance;
        _;
    }

    modifier isETHLeavingThePool() {
        if (msg.sig == this.provisionPodETH.selector) {
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
        recordPreviousBalance
        isETHLeavingThePool
        countCall("depositStakingRewards")
    {
        // bound the result between min deposit amount and uint64.max value ~18.44 ETH
        stakingRewardsAmount = bound(stakingRewardsAmount, 0.01 ether, uint256(type(uint64).max));

        vm.deal(address(this), stakingRewardsAmount);
        vm.startPrank(address(this));
        (bool success,) = address(pool).call{ value: stakingRewardsAmount }("");
        vm.stopPrank();
        require(success);

        ghost_eth_rewards_amount += stakingRewardsAmount;
    }

    // User deposits ETH to get pufETH
    function depositETH(address depositor, uint256 amount)
        public
        fuzzedAddress(depositor)
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
        uint256 pufETHAmount = pool.depositETH{ value: amount }(depositor);
        vm.stopPrank();

        uint256 afterBalance = pool.balanceOf(depositor);

        ghost_eth_deposited_amount += amount;

        require(expectedPufETHAmount == afterBalance - prevBalance, "pufETH calculation is wrong");
        require(pufETHAmount == expectedPufETHAmount, "amounts dont match");

        // Store the depositor and amount of pufETH
        (, uint256 prevAmount) = _pufETHDepositors.tryGet(depositor);
        _pufETHDepositors.set(depositor, prevAmount + expectedPufETHAmount);
    }

    // pufETH withdras pufETH -> ETH
    function burnPufETH(uint256 withdrawerSeed, address depositor, uint256 depositAmount)
        public
        recordPreviousBalance
        isETHLeavingThePool
        countCall("burnPufETH")
    {
        // If there are no pufETH holders, deposit ETH
        if (_pufETHDepositors.length() == 0) {
            return depositETH(depositor, depositAmount);
        }

        uint256 withdrawerIndex = withdrawerSeed % _pufETHDepositors.length();

        (address withdrawer, uint256 amount) = _pufETHDepositors.at(withdrawerIndex);

        // Due to limited liquidity in WithdrawalPool, we are withdrawing 1/3 of the user's balance at a time
        uint256 burnAmount = amount / 3;

        WithdrawalPool.Permit memory permit;
        permit.owner = withdrawer;
        permit.amount = burnAmount;

        vm.startPrank(withdrawer);
        pool.approve(address(withdrawalPool), type(uint256).max);
        withdrawalPool.withdrawETH(withdrawer, permit);
        vm.stopPrank();

        _pufETHDepositors.set(withdrawer, amount - burnAmount);
    }

    // function createPodAccount(address podAccountOwner)
    //     public
    //     fuzzedAddress(podAccountOwner)
    //     recordPreviousBalance
    //     isETHLeavingThePool
    //     countCall("createPodAccount")
    // {
    //     // Prevent duplicates
    //     if (!_podAccountOwners.add(podAccountOwner)) {
    //         return;
    //     }

    //     address[] memory owners = new address[](1);
    //     owners[0] = podAccountOwner;

    //     pool.createPodAccount({
    //         podAccountOwners: owners,
    //         threshold: 1,
    //         podRewardsRecipient: podAccountOwner,
    //         emptyData: ""
    //     });
    // }

    // Registers Validator key
    function registerValidatorKey(address podAccountOwner, bytes32 pubKeyPart)
        public
        fuzzedAddress(podAccountOwner)
        recordPreviousBalance
        isETHLeavingThePool
        countCall("registerValidatorKey")
    {
        // Prevent duplicates
        if (!_podAccountOwners.add(podAccountOwner)) {
            return;
        }

        address[] memory owners = new address[](1);
        owners[0] = podAccountOwner;

        uint256 ethBondAmount = 16 ether;
        vm.deal(podAccountOwner, ethBondAmount);
        vm.startPrank(podAccountOwner);

        (Safe podAccount, IEigenPodProxy eigenPodProxy) = pool.createPodAccountAndRegisterValidatorKey{
            value: ethBondAmount
        }({
            podAccountOwners: owners,
            podAccountThreshold: 1,
            data: _getMockValidatorKeyData(pubKeyPart),
            podRewardsRecipient: podAccountOwner,
            emptyData: ""
        });

        vm.stopPrank();

        // Account for that deposited eth in ghost variable
        ghost_eth_deposited_amount += ethBondAmount;

        // Add EigenPodProxy to proxies set
        _eigenPodProxies.add(address(eigenPodProxy));

        // Save information about that eigen pod proxy
        _eigenPodProxiesData[address(eigenPodProxy)].owner = podAccount;
        _eigenPodProxiesData[address(eigenPodProxy)].pubKeyPart = pubKeyPart;
    }

    // Starts the validating process for a random EigenPodProxy
    function provisionPodETH(uint256 eigenPodProxySeed, address podAccountOwner, bytes32 pubKeyPart)
        public
        isETHLeavingThePool
        recordPreviousBalance
        countCall("provisionPodETH")
    {
        // If we don't have proxies, create and register validator key, then call this function again with the same params
        if (_eigenPodProxies.length() == 0) {
            registerValidatorKey(podAccountOwner, pubKeyPart);
            return provisionPodETH(eigenPodProxySeed, podAccountOwner, pubKeyPart);
        }

        uint256 eigePodProxyIndex = eigenPodProxySeed % _eigenPodProxies.length();

        // Fetch EigenPodProxy from the set
        address proxy = _eigenPodProxies.at(eigePodProxyIndex);

        // ATM we only test with 1 validator per 1 eigen pod proxy
        // TODO: change that
        bytes32 pubKeypart = _eigenPodProxiesData[proxy].pubKeyPart;

        address[] memory enclaveAddresses =
            pool.getGuardianModule().getGuardiansEnclaveAddresses(pool.getGuaridnasMultisig());

        bytes[] memory enclaveSignatures = new bytes[](enclaveAddresses.length);

        IPufferPool.ValidatorKeyData memory validatorData = _getMockValidatorKeyData(pubKeypart);

        bytes32 msgToBeSigned = pool.getMessageToBeSigned({
            eigenPodProxy: proxy,
            pubKey: validatorData.blsPubKey,
            signature: new bytes(0),
            depositDataRoot: bytes32("")
        });

        // Manually sort enclaveSignatures by addresses that signed them
        // Signatures need to be in ascending order based on the address of the PK that signed them
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardiansEnclavePks[0], msgToBeSigned);
        bytes memory signature = abi.encodePacked(r, s, v);
        enclaveSignatures[0] = signature;
        (v, r, s) = vm.sign(guardiansEnclavePks[1], msgToBeSigned);
        signature = abi.encodePacked(r, s, v);
        enclaveSignatures[1] = signature;

        (v, r, s) = vm.sign(guardiansEnclavePks[2], msgToBeSigned);
        signature = abi.encodePacked(r, s, v);
        enclaveSignatures[2] = signature;

        pool.provisionPodETH({
            eigenPodProxy: address(proxy),
            pubKey: validatorData.blsPubKey,
            signature: new bytes(0),
            depositDataRoot: bytes32(""),
            guardianEnclaveSignatures: enclaveSignatures
        });

        // Remove that proxy
        _eigenPodProxies.remove(proxy);
    }

    // Stops the validator registration process
    function stopRegistration(uint256 eigenPodProxySeed, address podAccountOwner, bytes32 pubKeyPart)
        public
        isETHLeavingThePool
        countCall("stopRegistration")
        recordPreviousBalance
    {
        // If we don't have proxies, create and register validator key, then call this function again with the same params
        if (_eigenPodProxies.length() == 0) {
            return registerValidatorKey(podAccountOwner, pubKeyPart);
        }

        uint256 eigePodProxyIndex = eigenPodProxySeed % _eigenPodProxies.length();

        // Fetch EigenPodProxy from the set
        IEigenPodProxy proxy = IEigenPodProxy(_eigenPodProxies.at(eigePodProxyIndex));

        Data memory data = _eigenPodProxiesData[address(proxy)];

        bytes memory pubKey = _getPubKey(data.pubKeyPart);

        vm.startPrank(address(data.owner));
        proxy.stopRegistration(keccak256(pubKey));
        vm.stopPrank();
    }

    function callSummary() external view {
        console.log("Call summary:");
        console.log("-------------------");
        console.log("depositStakingRewards", calls["depositStakingRewards"]);
        console.log("depositETH", calls["depositETH"]);
        console.log("burnPufETH", calls["burnPufETH"]);
        console.log("createPodAccount", calls["createPodAccount"]);
        console.log("registerValidatorKey", calls["registerValidatorKey"]);
        console.log("provisionPodETH", calls["provisionPodETH"]);
        console.log("-------------------");
    }

    // No RAVE or anything, 16 ETH bond
    function _getMockValidatorKeyData(bytes32 pubKeypart) internal pure returns (IPufferPool.ValidatorKeyData memory) {
        // key length must be 48 bytes
        // bytes memory pubKey = new bytes(48);
        bytes memory pubKey = _getPubKey(pubKeypart);

        bytes[] memory blsEncryptedPrivKeyShares = new bytes[](0);
        bytes[] memory blsPubKeyShares = new bytes[](0);

        RaveEvidence memory evidence;

        IPufferPool.ValidatorKeyData memory validatorData = IPufferPool.ValidatorKeyData({
            blsPubKey: pubKey,
            signature: new bytes(0),
            depositDataRoot: bytes32(""),
            blsEncryptedPrivKeyShares: blsEncryptedPrivKeyShares,
            blsPubKeyShares: blsPubKeyShares,
            blockNumber: 1,
            evidence: evidence
        });

        return validatorData;
    }

    function _getPubKey(bytes32 pubKeypart) internal pure returns (bytes memory) {
        return bytes.concat(abi.encodePacked(pubKeypart), bytes16(""));
    }
}
