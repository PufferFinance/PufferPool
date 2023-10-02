// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { SafeProxy } from "safe-contracts/proxies/SafeProxy.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { DeploySafe } from "scripts/DeploySafe.s.sol";
import { console } from "forge-std/console.sol";

contract FirstVersion {
    address immutable _treasury;

    uint256 internal _poolBalance;
    uint256 internal _treasuryBalance;

    constructor(address treasury) {
        _treasury = treasury;
    }

    fallback() external payable {
        _poolBalance += msg.value / 2;
        _treasuryBalance += msg.value / 2;
    }
}

contract SecondVersion {
    address immutable _treasury;

    constructor(address treasury) {
        _treasury = treasury;
    }

    fallback() external payable {
        _safeTransferETH(_treasury, 1);
        uint256 gasBefore = gasleft();
        _safeTransferETH(_treasury, 1);
        uint256 gasAfter = gasleft();
        // console.log(gasBefore - gasAfter, "gas");
        // _safeTransferETH(_treasury, 1);
    }

    function _safeTransferETH(address to, uint256 amount) internal {
        bool success;

        /// @solidity memory-safe-assembly
        assembly {
            // Transfer the ETH and store if it succeeded or not.
            success := call(gas(), to, amount, 0, 0, 0, 0)
        }

        require(success);
    }
}

contract ETHTransferTest is Test {
    FirstVersion firstVersion;
    SecondVersion secondVersion;
    Safe multisig;

    function setUp() public {
        (SafeProxyFactory proxyFactory, Safe safeImplementation) = new DeploySafe().run();

        address zeroAddress = address(0);
        address[] memory owners = new address[](1);
        owners[0] = address(this);

        SafeProxy proxy = proxyFactory.createProxyWithNonce({
            _singleton: address(safeImplementation),
            initializer: abi.encodeCall(
                Safe.setup, (owners, 1, zeroAddress, "", zeroAddress, zeroAddress, 0, payable(zeroAddress))
                ),
            saltNonce: 1
        });

        multisig = Safe(payable(address(proxy)));

        firstVersion = new FirstVersion(address(multisig));
        secondVersion = new SecondVersion(address(multisig));
    }

    // We do 2 transfers because zero value to some value is more expensive than non zero value to non zero value

    // In this version we do the accounting in the smart contract and we update state variables
    function testFirstVersion() public {
        address(firstVersion).call{ value: 1 ether }("");
        address(firstVersion).call{ value: 1 ether }("");
    }

    // In this version we transfer ETH to hardcoded {Safe}
    function testSecondVersion() public {
        address(secondVersion).call{ value: 1 ether }("");
        address(secondVersion).call{ value: 1 ether }("");
    }
}
