// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { SafeDeployer } from "puffer/SafeDeployer.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { Safe, Enum, ModuleManager, GuardManager } from "safe-contracts/Safe.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";

contract SimpleFeeSplitter {
    address payable public immutable treasury;

    constructor(address payable treasuryAddress) {
        treasury = treasuryAddress;
    }

    function splitMoney(address payable recipient) external payable {
        uint256 treasuryAmt = msg.value / 2;

        treasury.transfer(treasuryAmt);

        recipient.transfer(msg.value - treasuryAmt);
    }
}

contract Drainer {
    function drain() external {
        address(5).call{ value: address(this).balance }("");
    }
}

contract GuardianModuleTest is Test, SafeDeployer {
    GuardianModule module;
    Safe safe;
    SimpleFeeSplitter feeSplitter;

    function setUp() public {
        (SafeProxyFactory proxyFactory, Safe safeImplementation) = new DeploySafe().run();

        address[] memory owners = new address[](1);
        owners[0] = address(this);

        feeSplitter = new SimpleFeeSplitter(payable(makeAddr("treasury")));

        module = new GuardianModule(address(feeSplitter));

        // Deploy safe
        safe = _deploySafe({
            safeProxyFactory: address(proxyFactory),
            safeSingleton: address(safeImplementation),
            saltNonce: 0,
            owners: owners,
            threshold: 1,
            to: address(0),
            data: ""
        });

        // Enable module
        safe.execTransaction({
            to: address(safe),
            value: 0,
            data: abi.encodeCall(ModuleManager.enableModule, address(module)),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            signatures: _createSafeContractSignature()
        });

        // Enable Guard
        safe.execTransaction({
            to: address(safe),
            value: 0,
            data: abi.encodeCall(GuardManager.setGuard, address(module)),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            signatures: _createSafeContractSignature()
        });
    }

    // DelegateCall should fail
    function testSendingMoneyElswhereShouldFailDelegateCall() public {
        // Simulate sending rewards to {Safe}
        (bool s,) = address(safe).call{ value: 100 ether }("");
        require(s);

        // Deploy drainer and try to delegatecall to it
        Drainer drainer = new Drainer();

        vm.expectRevert(IGuardianModule.DelegateCallIsNotAllowed.selector);
        safe.execTransaction({
            to: address(drainer),
            value: 0,
            data: "",
            operation: Enum.Operation.DelegateCall,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            signatures: _createSafeContractSignature()
        });
    }

    // Sending ETH to any other address than the fee splitter should fail
    function testSendingMoneyElswhereShouldFail() public {
        // Simulate sending rewards to {Safe}
        (bool s,) = address(safe).call{ value: 100 ether }("");
        require(s);

        // try sending eth to Bob, it should revert
        vm.expectRevert(IGuardianModule.BadETHDestination.selector);
        safe.execTransaction({
            to: payable(makeAddr("bob")),
            value: address(safe).balance,
            data: "",
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            signatures: _createSafeContractSignature()
        });
    }

    // Sending ETH to fee splitter should work
    function testSendingMoneyToSplitter() public {
        // Simulate sending rewards to {Safe}
        (bool s,) = address(safe).call{ value: 100 ether }("");
        require(s);

        address bob = makeAddr("bob");

        assertEq(bob.balance, 0, "poor bob");

        safe.execTransaction({
            to: payable(address(feeSplitter)),
            value: address(safe).balance,
            data: abi.encodeCall(SimpleFeeSplitter.splitMoney, (payable(bob))),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            signatures: _createSafeContractSignature()
        });

        assertEq(bob.balance, 50 ether, "rich bob");
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
