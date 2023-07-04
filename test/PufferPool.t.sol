// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { PufferPool } from "puffer/PufferPool.sol";
import { PufferPoolMockUpgrade } from "test/mocks/PufferPoolMockUpgrade.sol";
import { IERC20Upgradeable } from "openzeppelin-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import { DeployPufferPool } from "scripts/DeployPufferPool.s.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { Multicall3 } from "test/mocks/Multicall3.sol";
import { WETH9 } from "test/mocks/Weth9.sol";
import { ETHDepositor } from "puffer/ETHDepositor.sol";
import { IWETH9 } from "puffer/interface/IWETH9.sol";

contract PufferPoolTest is Test {
    PufferPool pool;
    WETH9 weth;
    address depositor = makeAddr("depositor");

    ETHDepositor ethDepositor;
    Multicall3 multicall;

    SafeProxyFactory proxyFactory;
    Safe safeImplementation;

    function setUp() public {
        (proxyFactory, safeImplementation) = new DeploySafe().run();
        (pool, weth) = new DeployPufferPool().run();

        // Two ways of depositing ETH
        // 1. Simple ETHDepositor smart contract
        ethDepositor = new ETHDepositor(IWETH9(address(weth)), pool);
        // 2. MakerDAO's Multicall3
        multicall = new Multicall3();
    }

    // Test setup
    function testSetup() public {
        assertEq(pool.name(), "Puffer ETH");
        assertEq(pool.symbol(), "pufETH");
        assertEq(address(weth), pool.asset(), "underlying token");
        assertEq(address(this), pool.owner(), "owner");

        vm.expectRevert("Initializable: contract is already initialized");
        pool.initialize(IERC20Upgradeable(address(weth)));
    }

    // Test smart contract upgradeability (UUPS)
    function testUpgrade() public {
        vm.expectRevert();
        uint256 result = PufferPoolMockUpgrade(address(pool)).returnSomething();

        PufferPoolMockUpgrade newImplementation = new PufferPoolMockUpgrade();
        pool.upgradeTo(address(newImplementation));

        result = PufferPoolMockUpgrade(address(pool)).returnSomething();
        assertEq(result, 1337);
    }

    // Create guardian account
    function testCreateGuardianAccount(bytes32 mrenclave) public {
        address[] memory owners = new address[](1);

        owners[0] = address(this);

        Safe safe = pool.createGuardianAccount({
            safeProxyFactory: address(proxyFactory),
            safeImplementation: address(safeImplementation),
            mrenclave: mrenclave,
            guardiansWallets: owners,
            guardiansEnclavePubKeys: new bytes[](0)
        });

        assertTrue(safe.isOwner(address(this)), "bad owner");
        assertEq(safe.getThreshold(), 1, "threshold");
    }

    // Fuzz test for creating Pod account
    function testCreatePodAccount(bytes32 mrenclave, address owner1, address owner2) public {
        vm.assume(owner1 != address(0)); // address(0) can't be used
        vm.assume(owner2 != address(0));
        vm.assume(owner1 != address(1));
        vm.assume(owner2 != address(1)); // address(1) is special and can't be used in {Safe}
        vm.assume(owner1 != owner2);

        address[] memory owners = new address[](2);

        owners[0] = owner1;
        owners[1] = owner2;

        Safe safe = pool.createPodAccount({
            safeProxyFactory: address(proxyFactory),
            safeImplementation: address(safeImplementation),
            mrenclave: mrenclave,
            podWallets: owners,
            podEnclavePubKeys: new bytes[](0)
        });

        assertTrue(safe.isOwner(address(owner1)), "bad owner");
        assertTrue(safe.isOwner(address(owner2)), "bad owner2");
        assertEq(safe.getThreshold(), 1, "threshold");
    }

    // Deposit via MakerDao's Multicall3 smart contract
    function testDepositETHViaMulticall3() public {
        uint256 amount = 1 ether;

        // Wrap ETH -> WETH
        Multicall3.Call3Value memory call0 = Multicall3.Call3Value({
            target: address(weth),
            callData: abi.encodeCall(weth.deposit, ()),
            value: amount,
            allowFailure: false
        });

        // Approve WETH -> PufferPool
        Multicall3.Call3Value memory call1 = Multicall3.Call3Value({
            target: address(weth),
            callData: abi.encodeCall(weth.approve, (address(pool), amount)),
            value: 0,
            allowFailure: false
        });

        // Deposit to PufferPool for `depositor`
        Multicall3.Call3Value memory call2 = Multicall3.Call3Value({
            target: address(pool),
            callData: abi.encodeCall(pool.deposit, (amount, address(depositor))),
            value: 0,
            allowFailure: false
        });

        Multicall3.Call3Value[] memory calldatas = new Multicall3.Call3Value[](3);

        calldatas[0] = call0;
        calldatas[1] = call1;
        calldatas[2] = call2;

        // Depositor should start with zero shares
        assertEq(pool.balanceOf(depositor), 0, "should have zero shares");

        multicall.aggregate3Value{ value: amount }(calldatas);

        // Depositor should more than zero shares
        assertGt(pool.balanceOf(depositor), 0, "no shares received");
    }

    // Deposit via ETHDepositor smart contract
    function testDepositViaEthDepositor() public {
        // Depositor should start with zero shares
        assertEq(pool.balanceOf(depositor), 0, "should have zero shares");

        ethDepositor.deposit{ value: 1 ether }(depositor);

        // Depositor should more than zero shares
        assertGt(pool.balanceOf(depositor), 0, "no shares received");
    }
}
