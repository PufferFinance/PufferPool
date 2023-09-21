// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Safe } from "safe-contracts/Safe.sol";
import { IERC20Upgradeable } from "openzeppelin-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { IEnclaveVerifier } from "puffer/interface/IEnclaveVerifier.sol";
import { AVSParams } from "puffer/struct/AVSParams.sol";
import { Status } from "puffer/struct/Status.sol";
import { Validator } from "puffer/struct/Validator.sol";

/**
 * @title IPufferPool
 * @author Puffer Finance
 * @notice IPufferPool TODO:
 */
interface IPufferPool is IERC20Upgradeable {
    /**
     * @notice Thrown when the user tries to deposit a small amount of ETH
     * @dev Signature "0x6a12f104"
     */
    error InsufficientETH();

    /**
     * @notice Thrown when the Validators deposits wrong ETH amount
     * @dev Signature "0x2c5211c6"
     */
    error InvalidAmount();

    /**
     * @notice Thrown when the user is not authorized
     * @dev Signature "0x82b42900"
     */
    error Unauthorized();

    /**
     * @notice Emitted when the EigenLayer AVS status is changed
     * @param avs is the address of the Actively validated service on EigenLayer
     * @param configuration is the new AVS configuration
     * @dev Signature "0x97718ff76d4db1b484deb230468b44f3ec4a033907837fd95f99b5cac5331a8f"
     */
    event AVSConfigurationChanged(address avs, AVSParams configuration);

    /**
     * @param enclaveVerifier is the address of Enclave verifier contract
     * @dev Signature "0x60e300c919f110ebd183109296d6cd03856a84f64cb7acb91abde69baefd0d7e"
     */
    event EnclaveVerifierChanged(address enclaveVerifier);

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
     * @notice Emitted when the Execution rewards split rate in changed from `oldValue` to `newValue`
     * @dev Signature "0x27449eb3aaae64a55d5d46a9adbcc8e1e38857748959a38693d78c36b74eacff"
     */
    event ExecutionCommissionChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the Consensus rewards split rate in changed from `oldValue` to `newValue`
     * @dev Signature "0x9066ee0e03e4694bb525f39a319a26ed219db1f8045f1aa5d3d8ee5d826f8b0e"
     */
    event ConsensusCommissionChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the POD AVS commission is changed from `oldValue` to `newValue`
     * @dev Signature "0xc8bae083652b453155f90b7a5c39bc29bf290d6447172f49532abb28721ae548"
     */
    event AvsCommissionChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the non custodial bond requirement is changed from `oldValue` to `newValue`
     * @dev Signature "0x6f3499c1b9157d1e13e411188703fd40af51fe6d3c3b95f325af2db41ad452e8"
     */
    event NonCustodialBondRequirementChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the non enclave bond requirement is changed from `oldValue` to `newValue`
     * @dev signature "0x50e3aad3fe58c0addb7f600531ccc21d0790dd329e85d820dfe7a6dfc615f59d"
     */
    event NonEnclaveBondRequirementChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the Guaridan enclave measurements are changed
     * @dev signature "0x9a538ef1307d6ba0812109ae1345331f1a76ba6a7ed805a0b450c7d198c389ce"
     */
    event GuardianNodeEnclaveMeasurementsChanged(
        bytes32 oldMrenclave, bytes32 mrenclave, bytes32 oldMrsigner, bytes32 mrsigner
    );

    /**
     * @notice Emitted when the enclave bond requirement is changed from `oldValue` to `newValue`
     * @dev Signature "0xef8b2e3d8234f201774dbbf55aedb1aa0a5e5e3d0ffe3b4947e6a477be1d1747"
     */
    event EnclaveBondRequirementChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the treasury address changes from `oldTreasury` to `newTreasury`
     * @dev Signature "0x8c3aa5f43a388513435861bf27dfad7829cd248696fed367c62d441f62954496"
     */
    event TreasuryChanged(address oldTreasury, address newTreasury);

    /**
     * @notice Emitted when the guardians address changes from `oldGuardians` to `newGuardians`
     * @dev Signature "0x6ec152e1a709322ea96ec4d6e8c6acc29aeba80455657f617b6ac837b100654a"
     */
    event GuardiansChanged(address oldGuardians, address newGuardians);

    /**
     * @notice Emitted when the protocol fee changes from `oldValue` to `newValue`
     * @dev Signature "0xff4822c8e0d70b6faad0b6d31ab91a6a9a16096f3e70328edbb21b483815b7e6"
     */
    event ProtocolFeeRateChanged(uint256 oldValue, uint256 newValue);

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
     * @notice Returns the treasury address
     */
    function TREASURY() external view returns (address payable);

    /**
     * @notice Returns the ETH rewards amount from the last update
     */
    function getNewRewardsETHAmount() external view returns (uint256);

    /**
     * @notice Returns the address of the Withdrawal pool
     */
    function getWithdrawalPool() external view returns (address);

    /**
     * @notice Returns the address of the Consensus vault
     */
    function getConsensusVault() external view returns (address);

    /**
     * @notice Returns the address of the Execution rewards vault
     */
    function getExecutionRewardsVault() external view returns (address);

    /**
     * @notice Returns the Puffer Avs address
     */
    function getPufferAvsAddress() external view returns (address);

    /**
     * @notice Returns true if `avs` is enabled
     */
    function isAVSEnabled(address avs) external view returns (bool);

    /**
     * @notice Returns the pod avs commission for `avs`
     */
    function getAVSCommission(address avs) external view returns (uint256);

    /**
     * @notice Returns the minimum bond requirement for `avs`
     */
    function getMinBondRequirement(address avs) external view returns (uint256);

    /**
     * @notice Returns the pufETH -> ETH exchange rate. 10**18 represents exchange rate of 1
     */
    function getPufETHtoETHExchangeRate() external view returns (uint256);

    /**
     * @notice Returns AVS Commission
     */
    function getAvsCommission() external view returns (uint256);

    /**
     * @notice Returns Consensus Commission
     */
    function getConsensusCommission() external view returns (uint256);

    /**
     * @notice Returns Execution Commission
     */
    function getExecutionCommission() external view returns (uint256);

    /**
     * @notice Returns the Strategy Manager
     */
    function STRATEGY_MANAGER() external view returns (IStrategyManager);

    /**
     * @notice Returns the Guardians multisig
     */
    function GUARDIANS() external view returns (Safe);

    /**
     * @notice Returns the Enclave verifier
     */
    function getEnclaveVerifier() external view returns (IEnclaveVerifier);

    /**
     * @notice Returns the `mrenclave` and `mrsigner` values
     */
    function getGuardianEnclaveMeasurements() external returns (bytes32 mrenclave, bytes32 mrsigner);

    /**
     * @notice Returns the protocol fee rate in wad
     */
    function getProtocolFeeRate() external view returns (uint256);

    // ==== Only Guardians ====

    function updateETHBackingAmount(uint256 amount) external;

    // ==== Only Guardians end ====
}
