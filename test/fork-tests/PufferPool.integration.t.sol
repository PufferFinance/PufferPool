// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IntegrationTestHelper } from "../helpers/IntegrationTestHelper.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { console } from "forge-std/console.sol";
import "openzeppelin/token/ERC20/IERC20.sol";

interface MissingInInterface {
    function DEPOSIT_TYPEHASH() external view returns (bytes32);
    function nonces(address) external view returns (uint256);
}

contract PufferPoolIntegrationTest is IntegrationTestHelper {
    address bob; // bob address is -> 0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e
    uint256 bobSK;

    uint256 erc20MockMinterSK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    IStrategyManager eigenStrategyManager = IStrategyManager(0x3D2b8adb7970D6201025638B7Db41ad7f85373c2);
    address eigenERC20Mock = 0x0F2961A3ded5806C6eEB3159Fd2f433eDf7e6FeE;
    address eigenStrategy = 0xaaC95d2e9724e52181fF0eFa626088E68B1b356b;
    IDelegationManager eigenDelegationManager = IDelegationManager(0x7A76C4E691b18B66c05574c4f6A46462F5EEd4CB);

    address eigenMockOperator = 0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f; // Operator on Goerli

    address multicall = 0xcA11bde05977b3631167028862bE2a173976CA11;

    function setUp() public {
        (bob, bobSK) = makeAddrAndKey("bob");
        vm.label(eigenERC20Mock, "eigen20mocktoken");
        vm.label(eigenStrategy, "mock strategy");
        vm.label(address(eigenStrategyManager), "eigen strategy manager");
        deployContractsGoerli();
    }

    function testMulticallStrategyDepositOnGoerli() public {
        Multicall3.Call3Value[] memory calls = new Multicall3.Call3Value[](4);

        uint256 tokenAmount = 100 ether;

        // Call 1.
        // mint ERC20 mock to multicall contract
        // On mainnet this would be the `deposit eth to get WETH`
        calls[0] = Multicall3.Call3Value({
            target: eigenERC20Mock,
            allowFailure: false,
            value: 0,
            callData: abi.encodeWithSignature("mint(address,uint256)", multicall, tokenAmount)
        });

        // Call 2.
        // approve token from multicall to Eigen strategy manager
        calls[1] = Multicall3.Call3Value({
            target: eigenERC20Mock,
            allowFailure: false,
            value: 0,
            callData: abi.encodeWithSignature("approve(address,uint256)", address(eigenStrategyManager), tokenAmount)
        });

        uint256 expiry = block.timestamp + 1 minutes;

        bytes memory signature = _getSignature(bobSK, tokenAmount, expiry);

        // Call 3.
        // Call depositIntoStrategyWithSignature
        calls[2] = Multicall3.Call3Value({
            target: address(eigenStrategyManager),
            allowFailure: false,
            value: 0,
            callData: abi.encodeCall(
                IStrategyManager.depositIntoStrategyWithSignature,
                (IStrategy(eigenStrategy), IERC20(eigenERC20Mock), tokenAmount, vm.addr(bobSK), expiry, signature)
                )
        });

        IDelegationManager.SignatureWithExpiry memory emptySig;
        IDelegationManager.SignatureWithExpiry memory stakerSIgnature = _getSignerSignatureForDelegation(bobSK, expiry);

        // Delegate to operator with signature (contract version on goerli doesn't match the version from modules, I can't get signature to work)
        // But it should work when it is live

        // calls[3] = Multicall3.Call3Value({
        //     target: address(eigenDelegationManager),
        //     allowFailure: false,
        //     value: 0,
        //     callData: abi.encodeWithSignature("delegateToBySignature(address,address,uint256,bytes)", vm.addr(bobSK), address(eigenStrategyManager), expiry, stakerSIgnature.signature)
        // });

        // The UX on the web UI would require 1 signature from the user + a transaction to multicall

        vm.startBroadcast(bob);
        Multicall3(multicall).aggregate3Value(calls);
        vm.stopBroadcast();
    }

    function _getSignerSignatureForDelegation(uint256 stakerSK, uint256 expiry)
        internal
        returns (IDelegationManager.SignatureWithExpiry memory)
    {
        IDelegationManager.SignatureWithExpiry memory stakerSignatureAndExpiry;

        address staker = vm.addr(stakerSK);
        stakerSignatureAndExpiry.expiry = expiry;
        {
            bytes32 stakerStructHash = keccak256(
                abi.encode(
                    hex"b2a21c2f78b6ef501475a2971550fe4cedb86f0dec990e23909bfb01fd61c54c",
                    staker,
                    eigenMockOperator,
                    0,
                    expiry
                )
            );

            bytes32 digestHash = keccak256(
                abi.encodePacked(
                    "\x19\x01", hex"8cad95687ba82c2ce50e74f7b754645e5117c3a5bec8151c0726d5857980a866", stakerStructHash
                )
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(stakerSK, digestHash);
            stakerSignatureAndExpiry.signature = abi.encodePacked(r, s, v);
        }
        return stakerSignatureAndExpiry;
    }

    function _getSignature(uint256 stakerSK, uint256 amount, uint256 expiry) internal returns (bytes memory) {
        // uint256 nonceBefore = 0;
        // uint256 nonceBefore = MissingInInterface(address(eigenStrategyManager)).nonces(vm.addr(stakerSK)); // how to get real nonce
        uint256 nonceBefore = 0;
        bytes memory signature;

        {
            bytes32 structHash = keccak256(
                abi.encode(
                    bytes32(hex"0a564d4cfe5cb0d4ee082aab2ca54b8c48e129485a8f7c77766ab5ef0c3566f1"),
                    eigenStrategy,
                    eigenERC20Mock,
                    amount,
                    nonceBefore,
                    expiry
                )
            );
            // MissingInInterface(address(eigenStrategyManager)).DEPOSIT_TYPEHASH(), eigenStrategy, eigenERC20Mock, amount, nonceBefore, expiry

            bytes32 digestHash = keccak256(
                abi.encodePacked(
                    "\x19\x01", hex"281f991d05c6bb236e1c42c6db5f0e3f5fa29b3ee39a86f5a0842e3e7f0b9676", structHash
                )
            );

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(stakerSK, digestHash);

            signature = abi.encodePacked(r, s, v);
        }

        return signature;
    }
}

interface WETH9 {
    event Approval(address indexed src, address indexed guy, uint256 wad);
    event Deposit(address indexed dst, uint256 wad);
    event Transfer(address indexed src, address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    function allowance(address, address) external view returns (uint256);
    function approve(address guy, uint256 wad) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function decimals() external view returns (uint8);
    function deposit() external payable;
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function totalSupply() external view returns (uint256);
    function transfer(address dst, uint256 wad) external returns (bool);
    function transferFrom(address src, address dst, uint256 wad) external returns (bool);
    function withdraw(uint256 wad) external;
}

interface Multicall3 {
    struct Call {
        address target;
        bytes callData;
    }

    struct Call3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    struct Call3Value {
        address target;
        bool allowFailure;
        uint256 value;
        bytes callData;
    }

    struct Result {
        bool success;
        bytes returnData;
    }

    function aggregate(Call[] memory calls) external payable returns (uint256 blockNumber, bytes[] memory returnData);
    function aggregate3(Call3[] memory calls) external payable returns (Result[] memory returnData);
    function aggregate3Value(Call3Value[] memory calls) external payable returns (Result[] memory returnData);
    function blockAndAggregate(Call[] memory calls)
        external
        payable
        returns (uint256 blockNumber, bytes32 blockHash, Result[] memory returnData);
    function getBasefee() external view returns (uint256 basefee);
    function getBlockHash(uint256 blockNumber) external view returns (bytes32 blockHash);
    function getBlockNumber() external view returns (uint256 blockNumber);
    function getChainId() external view returns (uint256 chainid);
    function getCurrentBlockCoinbase() external view returns (address coinbase);
    function getCurrentBlockDifficulty() external view returns (uint256 difficulty);
    function getCurrentBlockGasLimit() external view returns (uint256 gaslimit);
    function getCurrentBlockTimestamp() external view returns (uint256 timestamp);
    function getEthBalance(address addr) external view returns (uint256 balance);
    function getLastBlockHash() external view returns (bytes32 blockHash);
    function tryAggregate(bool requireSuccess, Call[] memory calls)
        external
        payable
        returns (Result[] memory returnData);
    function tryBlockAndAggregate(bool requireSuccess, Call[] memory calls)
        external
        payable
        returns (uint256 blockNumber, bytes32 blockHash, Result[] memory returnData);
}
