// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Safe } from "safe-contracts/Safe.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { IERC20Upgradeable } from "openzeppelin-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";

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
     * @dev Signature "0x7f2d1d961b4cbafff19f21d113114b516b5f1e6c4737e4ecf361d8ab019574a6"
     */
    event ValidatorKeyRegistered(address eigenPodProxy, bytes pubKey);

    /**
     * @notice Emitted when the EigenLayer AVS status is changed
     * @param avs is the address of the Actively validated service on EigenLayer
     * @param configuration is the new AVS configuration
     * @dev Signature "0x97718ff76d4db1b484deb230468b44f3ec4a033907837fd95f99b5cac5331a8f"
     */
    event AVSConfigurationChanged(address avs, AVSParams configuration);

    /**
     * @param safeProxyFactory is the address of the new {Safe} proxy factory
     * @dev Signature "0xc3e8c5c8f40ba3a4be3207f225f804c87a3d7e6316ee9b32dfa383f87f51c800"
     */
    event SafeProxyFactoryChanged(address safeProxyFactory);

    /**
     * @param safeImplementation is the address of the new {Safe} implementation contract
     * @dev Signature "0x7deed74ce611e6c4a95846634fcd60af15a02e80c78e4692fb5455f094f60d43"
     */
    event SafeImplementationChanged(address safeImplementation);

    /**
     * @notice Emitted when the remaining 30 ETH is provisioned to the Validator
     * @param eigenPodProxy is the address of the EigenPod proxy contract
     * @param blsPubKey is the public key of the Validator
     * @param timestamp is the unix timestmap in seconds
     * @dev Signature "0x38d719b1216fcb012b932840fc8d66e25bb95b58137d2f54de7ffd0edfbdc885"
     */
    event ETHProvisioned(address eigenPodProxy, bytes blsPubKey, uint256 timestamp);

    /**
     * @notice Emitted when ETH is deposited to PufferPool
     * @param depositor is the depositor address
     * @param pufETHRecipient is the recipient address
     * @param pufETHRecipient is the recipient address
     * @param ethAmountDeposited is the ETH amount deposited
     * @param pufETHAmount is the pufETH amount received in return
     * @dev Signature "0xf5681f9d0db1b911ac18ee83d515a1cf1051853a9eae418316a2fdf7dea427c5"
     */
    event Deposited(address depositor, address pufETHRecipient, uint256 ethAmountDeposited, uint256 pufETHAmount);

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
     * @notice Emitted when Guardians create an account
     * @param account {Safe} account address
     * @dev Signature "0xffe8d6a65a1c220ce5b076d70345efdb48fc5e84f233acf312d6587505946dec"
     */
    event GuardianAccountCreated(address account);

    /**
     * @notice Emitted when Pod owners create an account
     * @param creator Creator address
     * @param account {Safe} account address
     * @param rewardsContract is the rewards contract
     * @dev Signature "0xdb59fdaec46a06b9c7c78b7780e8967a0003f7ad1696ec05ab7c035c5cef53c0"
     */
    event PodAccountCreated(address creator, address account, address rewardsContract);

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
     * @notice Emitted when the Commission Denominator is changed from `oldValue` to `newValue`
     */
    event CommissionDenominatorChanged(uint256 oldValue, uint256 newValue);

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
     * @notice Emitted when the protocol fee changes from `oldValue` to `newValue`
     * @dev Signature "0xff4822c8e0d70b6faad0b6d31ab91a6a9a16096f3e70328edbb21b483815b7e6"
     */
    event ProtocolFeeRateChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Emitted when the deposit rate changes from `oldValue` to `newValue`
     * @dev Signature "0x7aaf6e876013942206286cfff5091af2fa84c63a6f07b849acdc1e7eb91780c0"
     */
    event DepositRateChanged(uint256 oldValue, uint256 newValue);

    /**
     * @notice Deposits ETH and `recipient` receives pufETH in return
     * @dev Signature "0x2d2da806"
     */
    function depositETH(address recipient) external payable;

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
     * @notice Returns the index of the Beacon Chain ETH Strategy
     */
    function getBeaconChainETHStrategyIndex() external view returns (uint256);

    /**
     * @notice Returns the Beacon ETH Strategy
     */
    function getBeaconChainETHStrategy() external view returns (IStrategy);

    /**
     * @notice Returns the Strategy Manager
     */
    function getStrategyManager() external view returns (IStrategyManager);

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

    /**
     * @notice Returns the execution rewards comission
     * @param amount Is the total amount received
     * @return the comission amount
     */
    function getExecutionAmount(uint256 amount) external view returns (uint256);

    // ==== Only Guardians ====

    /**
     * @notice Verifies the deposit of the Validator, provides the remaining 30 ETH and starts the staking via EigenLayer
     */
    function provisionPodETH(
        address eigenPodProxy,
        bytes calldata pubkey,
        bytes calldata signature,
        bytes[] calldata guardianEnclaveSignatures,
        bytes32 depositDataRoot
    ) external;

    function updateETHBackingAmount(uint256 amount) external;

    // ==== Only Guardians end ====
}
