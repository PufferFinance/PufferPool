// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "scripts/BaseScript.s.sol";
import "forge-std/console.sol";

// Sends ETH to receiver from the env var PK
contract TransferEth is BaseScript {
	function run(address receiver, uint256 amount) external broadcast {
		receiver.call{ value: amount }("");
	}
}