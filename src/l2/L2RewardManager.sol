// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IConnext } from "@connext/interfaces/core/IConnext.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IXReceiver } from "@connext/interfaces/core/IXReceiver.sol";

contract L2RewardManager is IXReceiver {
    // The connext contract on the origin domain.
    IConnext public immutable connext;

    // The token to be paid on this domain
    IERC20 public immutable token;

    uint256 public totalAmount;

    address internal l1RewardRegistry;

    constructor(address _connext, address _token) {
        connext = IConnext(_connext);
        token = IERC20(_token);
    }

    function xReceive(
        bytes32 _transferId,
        uint256 _amount,
        address _asset,
        address _originSender,
        uint32 _origin,
        bytes memory _callData
    ) external returns (bytes memory) {
        // Check for the right token
        require(_asset == address(token), "Wrong asset received");
        // Enforce a cost to update the greeting
        require(_amount > 0, "Must pay at least 1 wei");

        // Unpack the _callData
        uint256 amount = abi.decode(_callData, (uint256));

        totalAmount += amount;
    }
}
