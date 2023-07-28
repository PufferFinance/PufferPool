// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Safe } from "safe-contracts/Safe.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { IERC20Upgradeable } from "openzeppelin-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";

/**
 * @title IPufferPool
 * @author Puffer Finance
 * @notice IPufferPool TODO:
 */
interface IPufferPool is IERC20Upgradeable {
    /**
     * TODO: figure out what we need here
     */
    struct EigenPodProxyInformation {
        address creator;
        bytes32 pubKeyHash;
        bytes32 mrenclave;
    }

    /**
     * @dev Validator Key data struct
     */
    struct ValidatorKeyData {
        bytes blsPubKey;
        bytes signature;
        bytes32 depositDataRoot;
        bytes[] blsEncPrivKeyShares;
        bytes[] blsPubKeyShares;
        uint256 blockNumber;
        bytes raveEvidence;
    }

    /**
     * @dev AVS Parameters
     */
    struct AVSParams {
        uint256 podAVSCommission;
        uint256 minReputationScore; // experimental... TODO: figure out
        uint8 minBondRequirement;
        bool enabled;
    }

    /**
     * @notice Thrown when the user tries to deposit a small amount of ETH
     */
    error InsufficientETH();

    /**
     * @notice Thrown when the Validators deposits wrong ETH amount
     */
    error InvalidAmount();

    /**
     * @notice Thrown when creation of Eigen Pod Proxy fails
     */
    error Create2Failed();

    /**
     * @notice Thrown when the BLS public key is not valid
     */
    error InvalidBLSPubKey();

    /**
     * @notice Thrown when the number of BLS private key shares doesn't match guardians number
     */
    error InvalidBLSPrivateKeyShares();

    /**
     * @notice Thrown when the number of BLS public key shares doesn't match guardians number
     */
    error InvalidBLSPublicKeyShares();

    /**
     * @notice Thrown when the user is not authorized
     */
    error Unauthorized();

    /**
     * @notice Thrown if the Guardians {Safe} wallet already exists
     */
    error GuardiansAlreadyExist();

    /**
     * @notice Thrown if the Eigen Pod Proxy address is not valid
     */
    error InvalidEigenPodProxy();

    /**
     * @notice Emitted when the Validator key is registered
     * @param eigenPodProxy is the address of Eigen Pod Proxy
     * @param pubKey is the validator public key
     */
    event ValidatorKeyRegistered(address eigenPodProxy, bytes pubKey);

    /**
     * @notice Emitted when the EigenLayer AVS status is changed
     * @param avs is the address of the Actively validated service on EigenLayer
     * @param configuration is the new AVS configuration
     */
    event AVSConfigurationChanged(address avs, AVSParams configuration);

    /**
     * @param safeProxyFactory is the address of the new {Safe} proxy factory
     */
    event SafeProxyFactoryChanged(address safeProxyFactory);

    /**
     * @param safeImplementation is the address of the new {Safe} implementation contract
     */
    event SafeImplementationChanged(address safeImplementation);

    /**
     * @notice Emitted when the remaining 30 ETH is provisioned to the Validator
     * @param eigenPodProxy is the address of the EigenPod proxy contract
     * @param validatorIdx is the index of the Validator
     * @param timestamp is the unix timestmap in seconds
     */
    event ETHProvisioned(address eigenPodProxy, uint256 validatorIdx, uint256 timestamp);

    /**
     * @notice Emitted when ETH is deposited to PufferPool
     * @param depositor is the depositor address
     * @param pufETHRecipient is the recipient address
     * @param pufETHRecipient is the recipient address
     * @param ethAmountDeposited is the ETH amount deposited
     * @param pufETHAmount is the pufETH amount received in return
     */
    event Deposited(address depositor, address pufETHRecipient, uint256 ethAmountDeposited, uint256 pufETHAmount);

    /**
     * @notice Emitted when pufETH is burned
     * @param withdrawer is the address that burned pufETH
     * @param ETHRecipient is the address received ETH
     * @param pufETHAmount is the pufETH amount burned
     * @param ETHAmount is the ETH amount received
     */
    event Withdrawn(address withdrawer, address ETHRecipient, uint256 pufETHAmount, uint256 ETHAmount);

    /**
     * @notice Emitted when Guardians create an account
     * @param account {Safe} account address
     */
    event GuardianAccountCreated(address account);

    /**
     * @notice Emitted when Pod owners create an account
     * @param creator Creator address
     * @param account {Safe} account address
     */
    event PodAccountCreated(address creator, address account);

    /**
     * @notice Emitted when the Execution rewards split rate in changed from `oldValue` to `newValue`
     */
    event ExecutionCommissionChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the Consensus rewards split rate in changed from `oldValue` to `newValue`
     */
    event ConsensusCommissionChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the POD AVS commission is changed from `oldValue` to `newValue`
     */
    event AvsCommissionChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the Commission Denominator is changed from `oldValue` to `newValue`
     */
    event CommissionDenominatorChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the non custodial bond requirement is changed from `oldValue` to `newValue`
     */
    event NonCustodialBondRequirementChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the non enclave bond requirement is changed from `oldValue` to `newValue`
     */
    event NonEnclaveBondRequirementChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the enclave bond requirement is changed from `oldValue` to `newValue`
     */
    event EnclaveBondRequirementChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the treasury address changes from `oldTreasury` to `newTreasury`
     */
    event TreasuryChanged(address oldTreasury, address newTreasury);

    /**
     * @notice Deposits ETH and `recipient` receives pufETH in return
     */
    function depositETH(address recipient) external payable;

    /**
     *
     * @notice Burns `pufETHAmount` from the transaction sender and sends ETH to the `ethRecipient`
     */
    function withdrawETH(address ethRecipient, uint256 pufETHAmount) external;

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
    function getTreasury() external view returns (address);

    /**
     * @notice Returns the ETH rewards amount from the last update
     */
    function getNewRewardsETHAmount() external view returns (uint256);

    /**
     * @notice Returns {Safe} implementation address
     */
    function getSafeImplementation() external view returns (address);

    /**
     * @notice Returns {Safe} proxy factory address
     */
    function getSafeProxyFactory() external view returns (address);

    /**
     * @notice Returns the Puffer Avs address
     */
    function getPufferAvsAddress() external view returns (address);

    /**
     * @notice Returns true if `avs` is enabled
     */
    function isAVSEnabled(address avs) external view returns (bool);

    /**
     * @notice Returns the pod avs comission for `avs`
     */
    function getAVSComission(address avs) external view returns (uint256);

    /**
     * @notice Returns the minimum bond requirement for `avs`
     */
    function getMinBondRequirement(address avs) external view returns (uint256);

    /**
     * @notice Returns the pufETH -> ETH exchange rate. 10**18 represents exchange rate of 1
     */
    function getPufETHtoETHExchangeRate() external view returns (uint256);

    /**
     * @notice Distributes all ETH to the pool and PodProxyOwner upon protocol exit
     */
    function withdrawFromProtocol(uint256 pufETHAmount, address podRewardsRecipient, uint256 bondAmount)
        external
        payable;

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
     * Returns Commission Denominator
     */
    function getCommissionDenominator() external view returns (uint256);

    /**
     * @notice Creates a pod's {Safe} multisig wallet
     * @param podAccountOwners is a Pod's wallet owner addresses
     * @param threshold is a number of required confirmations for a {Safe} transaction
     */
    function createPodAccount(address[] calldata podAccountOwners, uint256 threshold) external returns (Safe);

    /**
     * @notice Creates a Pod and registers a validator key
     * @param podAccountOwners Pod's wallet owner addresses
     * @param podAccountThreshold Number of required confirmations for a {Safe} transaction
     * @param data is a validator key data
     * @return Safe is a newly created {Safe} multisig instance
     * @return IEigenPodProxy is an address of a newly created Eigen Pod Proxy
     */
    function createPodAccountAndRegisterValidatorKey(
        address[] calldata podAccountOwners,
        uint256 podAccountThreshold,
        ValidatorKeyData calldata data
    ) external payable returns (Safe, IEigenPodProxy);

    /**
     * @notice Registers a validator key for a `podAccount`
     * @dev Sender is expected to send the correct ETH amount
     * @param podAccount is the address of the Eigen Pod Account
     * @param data is a validator key data
     * @return IEigenPodProxy is an address of a newly created Eigen Pod Proxy
     */
    function registerValidatorKey(address podAccount, ValidatorKeyData calldata data)
        external
        payable
        returns (IEigenPodProxy);

    /**
     * @notice Creates a guardian {Safe} multisig wallet
     * @param guardiansWallets Guardian's wallet addresses
     * @param threshold Number of required confirmations for a {Safe} transaction
     */
    function createGuardianAccount(address[] calldata guardiansWallets, uint256 threshold)
        external
        returns (Safe account);

    // /**
    //  * @notice Returns the Eigen pod proxy information
    //  * @param eigenPodProxy Eigen pod proxy address
    //  */
    // function getEigenPodProxyInfo(address eigenPodProxy) external view returns (EigenPodProxyInformation memory);

    // ==== Only Guardians ====

    /**
     * @notice Verifies the deposit of the Validator, provides the remaining 30 ETH and starts the staking via EigenLayer
     */
    function provisionPodETH(
        address eigenPodProxy,
        bytes calldata pubkey,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) external;

    function updateETHBackingAmount(uint256 amount) external;

    // ==== Only Guardians end ====
}
