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
     * @notice Thrown if the sender did not send enough ETH in the transaction
     * @dev Signature "0x242b035c"
     */
    error InvalidETHAmount();

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
     * @dev Signature "0x42966c68"
     */
    function burn(uint256 pufETHAmount) external;

    /**
     * @notice Calculates the equivalent pufETH amount for a given `amount` of ETH based on the current ETH:pufETH exchange rate
     * Suppose that the exchange rate is 1 : 1.05 and the user is wondering how much `pufETH` will he receive if he deposits `amount` ETH.
     *
     * outputAmount = amount * (1 / exchangeRate) // because the exchange rate is 1 to 1.05
     * outputAmount = amount * (1 / 1.05)
     * outputAmount = amount * 0.95238095238
     *
     * if the user is depositing 1 ETH, he would get 0.95238095238 pufETH in return
     *
     * @param amount The amount of ETH to be converted to pufETH
     * @dev Signature "0x1b5ebe05"
     * @return The equivalent amount of pufETH
     */
    function calculateETHToPufETHAmount(uint256 amount) external view returns (uint256);

    /**
     * @notice Calculates the equivalent ETH amount for a given `pufETHAmount` based on the current ETH:pufETH exchange rate
     *
     * Suppose that the exchange rate is 1 : 1.05 and the user is wondering how much `pufETH` will he receive if he wants to redeem `pufETHAmount` worth of pufETH.
     *
     * outputAmount = pufETHAmount * (1.05 / 1) // because the exchange rate is 1 to 1.05 (ETH to pufETH)
     * outputAmount = pufETHAmount * 1.05
     *
     * if the user is redeeming 1 pufETH, he would get 1.05 ETH in return
     *
     * NOTE: The calculation does not take in the account any withdrawal fee.
     *
     * @param pufETHAmount The amount of pufETH to be converted to ETH
     * @dev Signature "0x149a74ed"
     * @return The equivalent amount of ETH
     */
    function calculatePufETHtoETHAmount(uint256 pufETHAmount) external view returns (uint256);

    /**
     * @notice Returns the exchange rate of pufETH to ETH
     *
     * The exchange rate starts at 1:1, because there is equal amount of ETH and pufETH in the protocol.
     * As the Validators join and pay Smoothing Commitments, there will be more ETH than pufETH in the protocol,
     * meaning that the exchange rate will change.
     *
     * conversion rate = (deposits + rewards - penalties) / pufETH supply
     *
     * At the protocol’s inception, Bob stakes 10 ETH and receives 10 pufETH.
     * Then, after some time, the protocol earns 2 ETH of rewards from smoothing commitments and restaking.
     * Now Bob’s 10 pufETH is backed by 12 ETH, making the conversion rate (10+2−0)/10=1.2 ETH per pufETH.
     *
     * @dev Signature "0x38220d4d"
     * @return The current exchange rate of pufETH to ETH
     */
    function getPufETHtoETHExchangeRate() external view returns (uint256);

    /**
     * @notice Transfers `ethAmount` to `to`
     * @dev Signature "0x7b1a4909"
     */
    function transferETH(address to, uint256 ethAmount) external;
}
