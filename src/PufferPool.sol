// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { AbstractVault } from "puffer/AbstractVault.sol";
import { ERC20 } from "openzeppelin/token/ERC20/ERC20.sol";
import { ERC20Permit } from "openzeppelin/token/ERC20/extensions/ERC20Permit.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { PufferPoolStorage } from "puffer/struct/PufferPoolStorage.sol";
import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";

/**
 * @title PufferPool
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferPool is IPufferPool, AbstractVault, ERC20Permit, AccessManaged {
    using SafeTransferLib for address;

    constructor(PufferProtocol protocol, address initialAuthority)
        payable
        AbstractVault(protocol)
        ERC20("Puffer ETH", "pufETH")
        ERC20Permit("pufETH")
        AccessManaged(initialAuthority)
    { }

    /**
     * @notice no calldata automatically triggers the depositETH for `msg.sender`
     */
    receive() external payable {
        depositETH();
    }

    /**
     * @inheritdoc IPufferPool
     */
    function depositETH() public payable returns (uint256) {
        uint256 pufETHAmount = _calculateETHToPufETHAmount(msg.value);

        emit Deposited(msg.sender, msg.value, pufETHAmount);

        _mint(msg.sender, pufETHAmount);

        return pufETHAmount;
    }

    function depositETHWithoutMinting() public payable {
        // Deposit rewards through this function
    }

    function paySmoothingCommitment() external payable {
        emit ETHReceived(msg.value);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function burn(uint256 pufETHAmount) external {
        _burn(msg.sender, pufETHAmount);
    }

    function transferETH(address to, uint256 ethAmount) external restricted {
        to.safeTransferETH(ethAmount);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function calculateETHToPufETHAmount(uint256 amount) public view returns (uint256) {
        return _calculateETHToPufETHAmount(amount);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function calculatePufETHtoETHAmount(uint256 pufETHAmount) public view returns (uint256) {
        return FixedPointMathLib.mulWad(pufETHAmount, getPufETHtoETHExchangeRate());
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getPufETHtoETHExchangeRate() public view returns (uint256) {
        return _getPufETHtoETHExchangeRate();
    }

    function _getPufETHtoETHExchangeRate() internal view returns (uint256) {
        PufferPoolStorage memory data = PUFFER_PROTOCOL.getPuferPoolStorage();
        // slither-disable-next-line incorrect-equality
        if (data.pufETHTotalSupply == 0) {
            return FixedPointMathLib.WAD;
        }

        return FixedPointMathLib.divWad((data.lockedETH + data.ethAmount), data.pufETHTotalSupply);
    }

    /**
     * @dev Internal function for calculating the ETH to pufETH amount when ETH is being sent in the transaction
     */
    function _calculateETHToPufETHAmount(uint256 amount) internal view returns (uint256) {
        return FixedPointMathLib.divWad(amount, _getPufETHtoETHExchangeRate());
    }
}
