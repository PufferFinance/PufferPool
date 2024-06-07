// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IConnext } from "@connext/interfaces/core/IConnext.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { MintableERC20 } from "./MintableERC20.sol";
import { IXERC20Lockbox } from "pufETH/interface/IXERC20Lockbox.sol";

contract L1RewardRegistry {

    struct L1ToL2Message {
        uint40 timestamp;
        
        bytes32 rootHash;
    }

    // The connext contract on the origin domain.
    IConnext public immutable connext;
    // The token to be paid on this domain
    IERC20 public immutable token;
    IERC20 public immutable xToken;
    IXERC20Lockbox lockBox;
    uint32 public immutable destinationDomain;
    address internal l2RewardManager;
    bytes32 rootHash;

    // Slippage (in BPS) for the transfer set to 100% for this example
    uint256 public immutable slippage = 10000;

    constructor(address _connext, address _token, address _xToken, address _lockBox, uint32 _destinationDomain) {
        connext = IConnext(_connext);
        token = IERC20(_token);
        xToken = IERC20(_xToken);
        destinationDomain = _destinationDomain;
        lockBox = IXERC20Lockbox(_lockBox);
    }

    function setL2RewardManager(address _l2RewardManager) external {
        l2RewardManager = _l2RewardManager;
    }

    /**
     * @notice Mint and bridge pufETH to L2
     * @param _amount The mint amount
     * @param relayerFee The fee offered to relayers.
     */
    function mintAndBridge(uint256 _amount, uint256 relayerFee, bytes32 _rootHash) external payable {

        rootHash = _rootHash;
        MintableERC20(address(token)).mint(_amount);

        token.approve(address(lockBox), _amount);
        lockBox.deposit(_amount);

        // This contract approves transfer to Connext
        xToken.approve(address(connext), _amount);

        // Encode calldata for the target contract call
        bytes memory callData = abi.encode(_amount);

        connext.xcall{ value: relayerFee }(
            destinationDomain, // _destination: Domain ID of the destination chain
            l2RewardManager, // _to: address of the target contract
            address(xToken), // _asset: address of the token contract
            msg.sender, // _delegate: address that can revert or forceLocal on destination
            _amount, // _amount: amount of tokens to transfer
            slippage, // _slippage: max slippage the user will accept in BPS (e.g. 300 = 3%)
            callData // _callData: the encoded calldata to send
        );
    }
}
