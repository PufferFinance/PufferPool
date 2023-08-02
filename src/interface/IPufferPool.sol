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
     * @dev Signature "0x6a12f104"
     */
    error InsufficientETH();

    /**
     * @notice Thrown when the Validators deposits wrong ETH amount
     * @dev Signature "0x2c5211c6"
     */
    error InvalidAmount();

    /**
     * @notice Thrown when creation of Eigen Pod Proxy fails
     * @dev Signature "0x04a5b3ee"
     */
    error Create2Failed();

    /**
     * @notice Thrown when the BLS public key is not valid
     * @dev Signature "0x7eef7967"
     */
    error InvalidBLSPubKey();

    /**
     * @notice Thrown when the number of BLS private key shares doesn't match guardians number
     * @dev Signature "0x2c8f9aa3"
     */
    error InvalidBLSPrivateKeyShares();

    /**
     * @notice Thrown when the number of BLS public key shares doesn't match guardians number
     * @dev Signature "0x9a5bbd69"
     */
    error InvalidBLSPublicKeyShares();

    /**
     * @notice Thrown when the user is not authorized
     * @dev Signature "0x82b42900"
     */
    error Unauthorized();

    /**
     * @notice Thrown if the Guardians {Safe} wallet already exists
     * @dev Signature "0xb8c56ff1"
     */
    error GuardiansAlreadyExist();

    /**
     * @notice Emitted when the Validator key is registered
     * @param eigenPodProxy is the address of Eigen Pod Proxy
     * @param pubKey is the validator public key
     * @dev Signature "0x7f2d1d96"
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
     * @dev Signature "0xc3e8c5c8"
     */
    event SafeProxyFactoryChanged(address safeProxyFactory);

    /**
     * @param safeImplementation is the address of the new {Safe} implementation contract
     * @dev Signature "0x7deed74c"
     */
    event SafeImplementationChanged(address safeImplementation);

    /**
     * @notice Emitted when the remaining 30 ETH is provisioned to the Validator
     * @param eigenPodProxy is the address of the EigenPod proxy contract
     * @param validatorIdx is the index of the Validator
     * @param timestamp is the unix timestmap in seconds
     * @dev Signature "0x3211f33a"
     */
    event ETHProvisioned(address eigenPodProxy, uint256 validatorIdx, uint256 timestamp);

    /**
     * @notice Emitted when ETH is deposited to PufferPool
     * @param depositor is the depositor address
     * @param pufETHRecipient is the recipient address
     * @param pufETHRecipient is the recipient address
     * @param ethAmountDeposited is the ETH amount deposited
     * @param pufETHAmount is the pufETH amount received in return
     * @dev Signature "0xf5681f9d"
     */
    event Deposited(address depositor, address pufETHRecipient, uint256 ethAmountDeposited, uint256 pufETHAmount);

    /**
     * @notice Emitted when pufETH is burned
     * @param withdrawer is the address that burned pufETH
     * @param ETHRecipient is the address received ETH
     * @param pufETHAmount is the pufETH amount burned
     * @param ETHAmount is the ETH amount received
     * @dev Signature "0x91fb9d98"
     */
    event Withdrawn(address withdrawer, address ETHRecipient, uint256 pufETHAmount, uint256 ETHAmount);

    /**
     * @notice Emitted when Guardians create an account
     * @param account {Safe} account address
     * @dev Signature "0xffe8d6a6"
     */
    event GuardianAccountCreated(address account);

    /**
     * @notice Emitted when Pod owners create an account
     * @dev Signature "0xbacf7df3"
     * @param creator Creator address
     * @param account {Safe} account address
     * @dev Signature "0xbacf7df3"
     */
    event PodAccountCreated(address creator, address account);

    /**
     * @notice Emitted when the Execution rewards split rate in changed from `oldValue` to `newValue`
     * @dev Signature "0x27449eb3"
     */
    event ExecutionCommissionChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the Consensus rewards split rate in changed from `oldValue` to `newValue`
     */
    event ConsensusCommissionChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the POD AVS commission is changed from `oldValue` to `newValue`
     * @dev Signature "0x9066ee0e"
     */
    event AvsCommissionChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the non custodial bond requirement is changed from `oldValue` to `newValue`
     * @dev Signature "0x6f3499c1"
     */
    event NonCustodialBondRequirementChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the non enclave bond requirement is changed from `oldValue` to `newValue`
     */
    event NonEnclaveBondRequirementChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the enclave bond requirement is changed from `oldValue` to `newValue`
     * @dev Signature "0x50e3aad3"
     */
    event EnclaveBondRequirementChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the treasury address changes from `oldTreasury` to `newTreasury`
     * @dev Signature "0x8c3aa5f4"
     */
    event TreasuryChanged(address oldTreasury, address newTreasury);

    /**
     * @notice Deposits ETH and `recipient` receives pufETH in return
     * @dev Signature "0x2d2da806"
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
    function withdrawFromProtocol(
        uint256 pufETHAmount,
        uint256 skimmedPodRewards,
        uint256 poolRewards,
        address podRewardsRecipient,
        uint8 bondAmount
    ) external payable;

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
     * @param podRewardsRecipient is the address of the Rewards recipient
     * @return Safe is a newly created {Safe} multisig instance
     * @return IEigenPodProxy is an address of a newly created Eigen Pod Proxy
     */
    function createPodAccountAndRegisterValidatorKey(
        address[] calldata podAccountOwners,
        uint256 podAccountThreshold,
        ValidatorKeyData calldata data,
        address podRewardsRecipient
    ) external payable returns (Safe, IEigenPodProxy);

    /**
     * @notice Registers a validator key for a `podAccount`
     * @dev Sender is expected to send the correct ETH amount
     * @param podAccount is the address of the Eigen Pod Account
     * @param podRewardsRecipient is the address of the Rewards recipient
     * @param data is a validator key data
     * @return IEigenPodProxy is an address of a newly created Eigen Pod Proxy
     */
    function registerValidatorKey(address podAccount, address podRewardsRecipient, ValidatorKeyData calldata data)
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

    /**
     * @notice Calculates and returns EigenPodProxy and EigenPod addresses based on `blsPubKey`
     * @dev Creation of EigenPodProxy and EigenPod is done via `create2` opcode.
     *      For EigenPodProxy the salt is keccak256(blsPubKey), and for EigenPod it is the `msg.sender`.
     *      In our case that will be EigenPodProxy.
     *      If we know address of the EigenPodProxy, we can calculate address of the EigenPod
     * @return EigenPodProxy address (Puffer Finance)
     * @return Eigen Pod Address (Eigen Layer)
     */
    function getEigenPodProxyAndEigenPod(bytes calldata blsPubKey) external view returns (address, address);

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
