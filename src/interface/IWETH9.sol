// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0;

import { IERC20 } from "openzeppelin/interfaces/IERC20.sol";

interface IWETH9 is IERC20 {
    function deposit() external payable;
}
