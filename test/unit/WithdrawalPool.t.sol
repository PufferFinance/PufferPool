// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IWithdrawalPool } from "puffer/interface/IWithdrawalPool.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { console } from "forge-std/console.sol";

contract WithdrawalPoolTest is TestHelper {
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

    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();
        _skipDefaultFuzzAddresses();
    }

    // Test withdraw ETH if there is neough liquidity
    function testWithdrawETH() public {
        address bob = makeAddr("bob");

        vm.deal(address(withdrawalPool), 100 ether);
        vm.deal(bob, 10 ether);

        address charlie = makeAddr("charlie");

        assertTrue(charlie.balance == 0, "charlie should be poor");

        vm.startPrank(bob);
        pool.depositETH{ value: 10 ether }();

        pool.approve(address(withdrawalPool), type(uint256).max);
        withdrawalPool.withdrawETH(charlie, 1 ether);

        assertTrue(charlie.balance != 0, "charlie got ETH");
    }

    // Depositor deposits and gives his signature so the withdrawer can take that signature and submit it to get the ETH
    function testWithdrawETHWithSignature() public {
        vm.deal(address(withdrawalPool), 1000 ether);

        string memory addressSeed = "pufETHDepositor";
        address pufETHDepositor = makeAddr(addressSeed);

        _TestTemps memory temp = _testTemps(addressSeed, address(withdrawalPool), 50 ether, block.timestamp);

        IWithdrawalPool.Permit memory permit = _signPermit(temp);

        vm.deal(pufETHDepositor, 1000 ether);

        address charlie = makeAddr("charlie");

        assertTrue(charlie.balance == 0, "charlie should be poor");

        vm.prank(pufETHDepositor);
        pool.depositETH{ value: 1000 ether }();

        withdrawalPool.withdrawETH(charlie, permit);

        assertTrue(charlie.balance != 0, "charlie got ETH");
    }

    // Modified from https://github.com/Vectorized/solady/blob/2ced0d8382fd0289932010517d66efb28b07c3ce/test/ERC20.t.sol
    function _signPermit(_TestTemps memory t) internal view returns (IWithdrawalPool.Permit memory p) {
        bytes32 innerHash = keccak256(abi.encode(_PERMIT_TYPEHASH, t.owner, t.to, t.amount, t.nonce, t.deadline));
        bytes32 domainSeparator = pool.DOMAIN_SEPARATOR();
        bytes32 outerHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, innerHash));
        (t.v, t.r, t.s) = vm.sign(t.privateKey, outerHash);

        return
            IWithdrawalPool.Permit({ owner: t.owner, deadline: t.deadline, amount: t.amount, v: t.v, r: t.r, s: t.s });
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
}
