// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { PufferPoolMockUpgrade } from "test/mocks/PufferPoolMockUpgrade.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { AVSParams } from "puffer/struct/AVSParams.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { RaveEvidence } from "puffer/interface/RaveEvidence.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { GuardianHelper } from "./helpers/GuardianHelper.sol";
import { TestBase } from "./TestBase.t.sol";

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

contract PufferPoolTest is GuardianHelper, TestBase {
    using ECDSA for bytes32;

    event DepositRateChanged(uint256 oldValue, uint256 newValue);
    event ETHProvisioned(address eigenPodProxy, bytes blsPubKey, uint256 timestamp);

    address rewardsRecipient = makeAddr("rewardsRecipient");

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

    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();

        _skipDefaultFuzzAddresses();
    }

    // Internal function for creating a Validator Data
    function _getMockValidatorKeyData() internal pure returns (IPufferPool.ValidatorKeyData memory) {
        bytes[] memory newSetOfPubKeys = new bytes[](1);
        newSetOfPubKeys[0] = bytes("key1");

        // key length must be 48 bytes
        bytes memory pubKey = new bytes(48);

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

    // Test setup
    function testSetup() public {
        assertEq(pool.name(), "Puffer ETH");
        assertEq(pool.symbol(), "pufETH");
        assertEq(pool.paused(), false, "paused");
        assertEq(address(this), pool.owner(), "owner");

        vm.expectRevert("Initializable: contract is already initialized");
        pool.initialize({
            withdrawalPool: address(123),
            executionRewardsVault: address(512351234),
            consensusVault: address(412312443333333),
            guardianSafeModule: address(555123),
            enclaveVerifier: address(1231555324534),
            emptyData: ""
        });
    }

    function testSetProtocolFeeRate() public {
        uint256 rate = 20 * FixedPointMathLib.WAD;
        pool.setProtocolFeeRate(rate); // 20%
        assertEq(pool.getProtocolFeeRate(), rate, "new rate");
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

    // Fuzz test for depositing ETH to PufferPool
    function testDeposit(address depositor, uint256 depositAmount) public fuzzedAddress(depositor) {
        depositAmount = bound(depositAmount, 0.01 ether, 1_000_000 ether);

        vm.deal(depositor, depositAmount);

        vm.startPrank(depositor);
        assertEq(pool.balanceOf(depositor), 0, "recipient pufETH amount before deposit");

        pool.depositETH{ value: depositAmount }();
        vm.stopPrank();

        assertEq(pool.balanceOf(depositor), depositAmount, "recipient pufETH amount");
    }

    // // Deposits ETH and tries to get half of that back
    // function testDepositAndWithdrawal() public {
    //     uint256 depositAmount = 100 ether;
    //     address pufETHRecipient = makeAddr("pufETHRecipient");

    //     assertEq(pool.balanceOf(pufETHRecipient), 0, "recipient pufETH amount before deposit");

    //     // This is the only depositor in our pool, meaning he gets 1:1 pufETH for depositing
    //     pool.depositETH{ value: depositAmount }(pufETHRecipient);

    //     uint256 pufETHRecipientBalance = pool.balanceOf(pufETHRecipient);

    //     assertEq(depositAmount, pufETHRecipientBalance, "1:1 ratio");

    //     // Split ratio is 90%, meaning 90 ether stays in the pool
    //     assertEq(address(pool).balance, 90 ether, "not eth in the pool");

    //     // Our WithdrawalPool is empty, so we need to give it some ETH so that it can handle withdrawals
    //     // note: vm.deal overwrites the ETH amount in the withdrawal pool
    //     // Original deposit of 100 eth is split 90 -> depositPool, 10 -> withdrawalPool
    //     uint256 liquidityAmount = 110 ether;
    //     vm.deal(address(withdrawalPool), liquidityAmount);
    //     assertEq(address(withdrawalPool).balance, 110 ether, "withdrawalPool balance");
    //     assertEq(address(withdrawalPool).balance + address(pool).balance, 200 ether, "total balance");
    //     assertEq(pool.totalSupply(), 100 ether, "pufferPool total supply");

    //     // Ratio is now 1:2
    //     // 100 totalSupply and 200 ETH amount

    //     vm.startPrank(pufETHRecipient);
    //     // 2 step withdrawal
    //     // 1 approve pufETH to withdrawal pool
    //     pool.approve(address(withdrawalPool), type(uint256).max);

    //     WithdrawalPool.Permit memory permit;
    //     permit.owner = pufETHRecipient;
    //     permit.amount = 50 ether;

    //     // 2. withdraw
    //     withdrawalPool.withdrawETH(pufETHRecipient, permit);

    //     assertEq(100 ether, pufETHRecipient.balance, "amounts don't match");
    // }

    // // Deposits ETH and tries to get half of that back via permit signature
    // function testWithdrawalFlowWithPermit() public {
    //     uint256 depositAmount = 100 ether;
    //     string memory addressSeed = "pufETHDepositor";

    //     address pufETHDepositor = makeAddr(addressSeed);

    //     assertEq(pool.balanceOf(pufETHDepositor), 0, "recipient pufETH amount before deposit");

    //     // This is the only depositor in our pool, meaning he gets 1:1 pufETH for depositing
    //     pool.depositETH{ value: depositAmount }(pufETHDepositor);

    //     uint256 pufETHRecipientBalance = pool.balanceOf(pufETHDepositor);

    //     assertEq(depositAmount, pufETHRecipientBalance, "1:1 ratio");

    //     // Our WithdrawalPool is empty, so we need to give it some ETH so that it can handle withdrawals
    //     uint256 liquidityAmount = 110 ether;

    //     // Give eth to eth pool so that it has liquidity
    //     // Our WithdrawalPool is empty, so we need to give it some ETH so that it can handle withdrawals
    //     // note: vm.deal overwrites the ETH amount in the withdrawal pool
    //     // Original deposit of 100 eth is split 90 -> depositPool, 10 -> withdrawalPool
    //     vm.deal(address(withdrawalPool), liquidityAmount);

    //     vm.startPrank(pufETHDepositor);

    //     _TestTemps memory temp = _testTemps(addressSeed, address(withdrawalPool), 50 ether, block.timestamp);

    //     // Do a gasless signature
    //     WithdrawalPool.Permit memory permit = _signPermit(temp);

    //     // Create a new recipient address and withdraw to it
    //     address pufETHRecipient = makeAddr("recipient");

    //     // Approve is actually a permit signature
    //     withdrawalPool.withdrawETH(pufETHRecipient, permit);

    //     assertEq(100 ether, pufETHRecipient.balance, "recipient didn't get any ETH");
    // }

    // Tests setter for enclave measurements
    function testSetNodeEnclaveMeasurements(bytes32 mrsigner, bytes32 mrenclave) public {
        pool.setNodeEnclaveMeasurements(mrsigner, mrenclave);
        (bytes32 ms, bytes32 me) = pool.getNodeEnclaveMeasurements();
        assertTrue(mrsigner == ms, "mrsigner");
        assertTrue(mrenclave == me, "mrenclave");
    }

    // Tests setter for guardian enclave measurements
    function testGuardianEnclaveMeasurements(bytes32 mrsigner, bytes32 mrenclave) public {
        pool.setGuardianEnclaveMeasurements(mrsigner, mrenclave);
        (bytes32 ms, bytes32 me) = pool.getGuardianEnclaveMeasurements();
        assertTrue(mrsigner == ms, "mrsigner guardian");
        assertTrue(mrenclave == me, "mrenclave guardian");
    }

    // Test trying to register a duplicate vaidator key
    // function testRegisterDuplicateKey(address owner) public {
    //     vm.deal(owner, 100 ether);
    //     vm.startPrank(owner);
    //     pool.registerValidatorKey{ value: 16 ether }(eigenPodProxy, _getMockValidatorKeyData());
    //     vm.expectRevert(IPufferPool.PublicKeyIsAlreadyActive.selector);
    //     pool.registerValidatorKey{ value: 16 ether }(eigenPodProxy, _getMockValidatorKeyData());
    // }

    // Register validator key and then stop validator registration, it should return the bond
    // function testRegisterValidatorKeyAndStopRegistration(address owner) public {
    //     (Safe podAccount, IEigenPodProxy eigenPodProxy) = testCreatePodAccount(owner);

    //     vm.deal(owner, 100 ether);
    //     vm.prank(owner);
    //     pool.registerValidatorKey{ value: 16 ether }(eigenPodProxy, _getMockValidatorKeyData());

    //     bytes32 pubKeyHash = keccak256(_getMockValidatorKeyData().blsPubKey);

    //     vm.prank(address(podAccount));
    //     eigenPodProxy.stopRegistration(pubKeyHash);

    //     IPufferPool.ValidatorInfo memory info = pool.getValidatorInfo(address(eigenPodProxy), pubKeyHash);
    //     assertEq(info.bond, 0, "bond should be zero");
    //     assertTrue(info.status == IPufferPool.Status.BOND_WITHDRAWN, "status should be bond withdrawn");
    //     assertEq(pool.balanceOf(rewardsRecipient), 16 ether, "recipient should get 16 pufETH (original bond)");
    // }

    // Deposit should revert when trying to deposit too small amount
    function testDepositRevertsForTooSmallAmount() public {
        vm.expectRevert(IPufferPool.InsufficientETH.selector);
        pool.depositETH{ value: 0.005 ether }();
    }

    // Setter for execution rewards
    // function testSetExecutionCommission(uint256 newValue) public {
    //     pool.setExecutionCommission(newValue);
    //     assertEq(pool.getExecutionCommission(), newValue);
    // }

    // Setter for consensus rewards
    // function testSetConsensusCommission(uint256 newValue) public {
    //     pool.setConsensusCommission(newValue);
    //     assertEq(pool.getConsensusCommission(), newValue);
    // }

    // Setter for pod avs commission
    // function testSetAvsCommision(uint256 newValue) public {
    //     pool.setAvsCommission(newValue);
    //     assertEq(pool.getAvsCommission(), newValue);
    // }

    // Test configuring the AVS
    function testConfigureAVS(address avs, bool enabled) public {
        uint256 avsComission = 50e16;
        uint8 minBondRequirement = uint8(2);

        AVSParams memory cfg = AVSParams({
            podAVSCommission: avsComission,
            minReputationScore: 5,
            minBondRequirement: minBondRequirement,
            enabled: enabled
        });

        pool.changeAVSConfiguration(avs, cfg);
        assertEq(pool.isAVSEnabled(avs), enabled);
        assertEq(pool.getAVSCommission(avs), avsComission);
        assertEq(pool.getMinBondRequirement(avs), minBondRequirement);
    }

    // Modified from https://github.com/Vectorized/solady/blob/2ced0d8382fd0289932010517d66efb28b07c3ce/test/ERC20.t.sol
    function _signPermit(_TestTemps memory t) internal view returns (WithdrawalPool.Permit memory p) {
        bytes32 innerHash = keccak256(abi.encode(_PERMIT_TYPEHASH, t.owner, t.to, t.amount, t.nonce, t.deadline));
        bytes32 domainSeparator = pool.DOMAIN_SEPARATOR();
        bytes32 outerHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, innerHash));
        (t.v, t.r, t.s) = vm.sign(t.privateKey, outerHash);

        return WithdrawalPool.Permit({ owner: t.owner, deadline: t.deadline, amount: t.amount, v: t.v, r: t.r, s: t.s });
    }
}
