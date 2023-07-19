// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Safe } from "safe-contracts/Safe.sol";
import { EnumerableSet } from "openzeppelin/utils/structs/EnumerableSet.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";

/**
 * @title IPufferPool
 * @author Puffer Finance
 * @notice IPufferPool TODO:
 */
interface IPufferPool {
    /**
     * TODO: figure out what we need here
     */
    struct EigenPodProxyInformation {
        address creator;
        bytes32 mrenclave;
    }

    /**
     * @notice Thrown when the user tries to deposit a small amount of ETH
     */
    error InsufficientETH();

    /**
     * @notice Thrown when the user is not authorized
     */
    error Unauthorized();

    /**
     * @notice Thrown if the user tries to register the same Validator key on the same EigenPodProxy multiple times
     */
    error DuplicateValidatorKey(bytes pubKey);

    /**
     * @notice Thrown if the maximum number of validators is reached for that Eigen Pod Proxy
     */
    error MaximumNumberOfValidatorsReached();

    /**
     * @notice Thrown if the Guardians {Safe} wallet already exists
     */
    error GuardiansAlreadyExist();

    /**
     * @notice Thrown if the Eigen Pod Proxy address is not valid
     */
    error InvalidEigenPodProxy();

    event ValidatorKeyRegistered(address eigenPodProxy, bytes pubKey);

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
     * @param eigenPodProxy Eigen pod proxy contract
     */
    event PodAccountCreated(address creator, address account, address eigenPodProxy);

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
     * Returns the amount of ETH locked in Validators
     */
    function getLockedETHAmount() external view returns (uint256);

    /**
     * Returns the ETH rewards amount from the last update
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
     * Returns the pufETH -> ETH exchange rate. 10**18 represents exchange rate of 1
     */
    function getPufETHtoETHExchangeRate() external view returns (uint256);

    function getPodAVSComission() external view returns (uint256);

    function getConsensusRewardsSplit() external view returns (uint256);

    function getExecutionRewardsSplit() external view returns (uint256);

    /**
     * @notice Creates a pod's {Safe} multisig wallet
     * @param podAccountOwners is a Pod's wallet owner addresses
     * @param threshold is a number of required confirmations for a {Safe} transaction
     */
    function createPodAccount(address[] calldata podAccountOwners, uint256 threshold)
        external
        returns (Safe, IEigenPodProxy);

    /**
     * @param podAccountOwners Pod's wallet owner addresses
     * @param threshold Number of required confirmations for a {Safe} transaction
     * @param pubKeys is a list of Validator public keys
     * @return Safe is a newly created {Safe} multisig instance
     * @return IEigenPodProxy an address of a newly created Eigen Pod Proxy
     */
    function createPodAccountAndRegisterValidatorKeys(
        address[] calldata podAccountOwners,
        uint256 threshold,
        bytes[] calldata pubKeys
    ) external payable returns (Safe, IEigenPodProxy);

    /**
     * @notice Sender is expected to send ETH amount for number of pubKeys * bond amount
     * @param podAccount is the address of the Eigen Pod Account
     * @param pubKeys is an array of Validator pubKeys
     */
    function registerValidatorEnclaveKeys(address podAccount, bytes[] calldata pubKeys) external payable;

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

    // ==== Only Owner ====

    /**
     * Changes the {Safe} implementation address to `newSafeImplementation`
     */
    function changeSafeImplementation(address newSafeImplementation) external;

    /**
     * Changes the {Safe} proxy factory address to `newSafeFactory`
     */
    function changeSafeProxyFactory(address newSafeFactory) external;

    /**
     * Pauses the smart contract
     */
    function pause() external;

    /**
     * Unpauses the smart contract
     */
    function resume() external;

    // ==== Only Owner end ====

    // function provisionPod(
    //     bytes memory pubKey,
    //     bytes memory depositDataRoot,
    //     bytes memory depositSignature,
    //     bytes[] memory crewSignatures,
    //     bytes32 podType
    // ) external returns (bool success);

    // function upgradeCrew(address newCrewAddress) external returns (bool success);

    // function registerValidatorKey(
    //     bytes memory pubKey,
    //     bytes[] memory pubKeyShares,
    //     bytes[] memory encKeyShares,
    //     bytes memory depositDataRoot,
    //     bytes memory depositSignature,
    //     bytes[] memory podSignatures,
    //     bytes32 podType
    // ) external payable returns (bytes32 withdrawalCredentials);

    // function approveRestakeRequest(address targetContract, bytes32 podType) external payable returns (bool success);

    // function calcWithdrawalCredentials(bytes memory pubKey) external pure returns (address withdrawalCredentials);

    // function ejectPodForInactivity(
    //     address podAccount,
    //     bytes32 podType,
    //     bytes32 beaconStateRoot,
    //     uint256 validatorIndex,
    //     bytes[] memory crewSignatures
    // ) external;

    // function ejectPodForTheft(
    //     address podAccount,
    //     bytes32 podType,
    //     bytes32 beaconStateRoot,
    //     uint256 validatorIndex,
    //     bytes memory validatorPubKey,
    //     bytes[] memory crewSignatures
    // ) external;

    // // Setters to set parameters
    // function setParamX() external;

    // // Getters to get parameters
    // function getParamX() external returns (uint256 X);
}
