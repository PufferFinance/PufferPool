// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IERC20 } from "openzeppelin/token/ERC20/IERC20.sol";

/**
 * @title IPufferPool
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferPool is IERC20 {
    /**
     * Thrown if the "rescued" token is pufETH
     * @dev Signature "0x961c9a4f"
     */
    error InvalidToken(address token);

    /**
     * @notice Emitted when ETH is deposited to PufferPool
     * @param pufETHRecipient is the recipient address
     * @param ethAmountDeposited is the ETH amount deposited
     * @param pufETHAmount is the pufETH amount received in return
     * @dev Signature "0x73a19dd210f1a7f902193214c0ee91dd35ee5b4d920cba8d519eca65a7b488ca"
     */
    event Deposited(address pufETHRecipient, uint256 ethAmountDeposited, uint256 pufETHAmount);

    /**
     * @notice Deposits ETH and `msg.sender` receives pufETH in return
     * @return pufETH amount minted
     * @dev Signature "0xf6326fb3"
     */
    function depositETH() external payable returns (uint256);

    /**
     *
     * @notice Burns `pufETHAmount` from the transaction sender
     */
    function burn(uint256 pufETHAmount) external;

    /**
     * @notice Calculates ETH -> pufETH `amount` based on the ETH:pufETH exchange rate
     * @return pufETH amount
     */
    function calculateETHToPufETHAmount(uint256 amount) external view returns (uint256);

    /**
     * @notice Calculates pufETH -> ETH `pufETHAmount` based on the ETH:pufETH exchange rate
     * @return ETH amount
     */
    function calculatePufETHtoETHAmount(uint256 pufETHAmount) external view returns (uint256);

    /**
     * @notice Returns the pufETH -> ETH exchange rate. 10**18 represents exchange rate of 1
     */
    function getPufETHtoETHExchangeRate() external view returns (uint256);

    /**
     * @notice Transfers `ethAmount` to `to`
     */
    function transferETH(address to, uint256 ethAmount) external;
}
