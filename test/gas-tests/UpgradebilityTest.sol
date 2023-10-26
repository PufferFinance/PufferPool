// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { ERC1967Proxy } from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

contract FirstVersion is UUPSUpgradeable {
    uint256 public number;

    function initialize(uint256 value) public initializer {
        __UUPSUpgradeable_init();
        number = value;
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override { }
}

contract Upgraded is UUPSUpgradeable {
    // Rename the state variable 
    uint256 public originalNumber;

    // Create a getter that will return whatever
    function number() external pure returns (uint256) {
        return 1337;
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override { }
}

contract UpgradebilityTest is Test {
    FirstVersion target;

    function setUp() public {
        address impl = address(new FirstVersion());

        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), "");

        target = FirstVersion(payable(address(proxy)));
        target.initialize(1234);
    }

    function testIfTheValueCanBeFlipped() external {
        // Original value was 1234
        assertEq(target.number(), 1234, "setup");

        address upgradedImpl = address(new Upgraded());

        target.upgradeToAndCall(upgradedImpl, "");

        // Upgraded value 1337
        assertEq(target.number(), 1337, "setup");
    }
}
