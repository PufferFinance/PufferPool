// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title IPufferPool
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IPufferPool {
    /**
     * @notice Thrown when the user tries to deposit a small amount of ETH
     * @dev Signature "0x6a12f104"
     */
    error InsufficientETH();

    /**
     * @notice Thrown when the user is not authorized
     * @dev Signature "0x82b42900"
     */
    error Unauthorized();

    /**
     * @notice Emitted when ETH is deposited to PufferPool
     * @param pufETHRecipient is the recipient address
     * @param ethAmountDeposited is the ETH amount deposited
     * @param pufETHAmount is the pufETH amount received in return
     * @dev Signature "0x73a19dd210f1a7f902193214c0ee91dd35ee5b4d920cba8d519eca65a7b488ca"
     */
    event Deposited(address pufETHRecipient, uint256 ethAmountDeposited, uint256 pufETHAmount);

    /**
     * @notice Emitted when pufETH is burned
     * @param withdrawer is the address that burned pufETH
     * @param ETHRecipient is the address received ETH
     * @param pufETHAmount is the pufETH amount burned
     * @param ETHAmount is the ETH amount received
     * @dev Signature "0x91fb9d98b786c57d74c099ccd2beca1739e9f6a81fb49001ca465c4b7591bbe2"
     */
    event Withdrawn(address withdrawer, address ETHRecipient, uint256 pufETHAmount, uint256 ETHAmount);

    /**
     * @notice Emitted when the PufferPool receives execution commitment ETH / donation
     * @dev Signature "0x27f12abfe35860a9a927b465bb3d4a9c23c8428174b83f278fe45ed7b4da2662"
     */
    event ETHReceived(uint256 ethAmount);

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
     * @notice Returns the amount of ETH locked in Validators
     */
    function getLockedETHAmount() external view returns (uint256);

    /**
     * @notice Returns the ETH rewards amount from the last update
     */
    function getNewRewardsETHAmount() external view returns (uint256);

    /**
     * @notice Returns the pufETH -> ETH exchange rate. 10**18 represents exchange rate of 1
     */
    function getPufETHtoETHExchangeRate() external view returns (uint256);

    // ==== Only Guardians ====

    function updateETHBackingAmount(uint256 amount) external;

    // ==== Only Guardians end ====
}
