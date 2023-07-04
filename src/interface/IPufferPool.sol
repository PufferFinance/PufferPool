// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Safe } from "safe-contracts/Safe.sol";

/**
 * @title IPufferPool
 * @author Puffer Finance
 * @notice IPufferPool TODO:
 */
interface IPufferPool {
    /**
     * @notice Thrown when the user tries to deposit a small amount of ETH
     */
    error AmountTooSmall();

    /**
     * @notice Thrown when the user is not authorized
     */
    error Unauthorized();

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
     * @param mrenclave Unique enclave identifier
     * @param account {Safe} account address
     */
    event GuardianAccountCreated(bytes32 mrenclave, address account);

    /**
     * @notice Emitted when Pod owners create an account
     * @param mrenclave Unique enclave identifier
     * @param account {Safe} account address
     */
    event PodAccountCreated(bytes32 mrenclave, address account);

    /**
     * @notice Deposits ETH and `recipient` receives pufETH in return
     */
    function deposit(address recipient) external payable;

    /**
     *
     * @notice Burns `pufETHAmount` from the transaction sender and sends ETH to the `ethRecipient`
     */
    function withdraw(address ethRecipient, uint256 pufETHAmount) external;

    /**
     * Pauses the smart contract
     */
    function pause() external;

    /**
     * Unpauses the smart contract
     */
    function resume() external;

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
     * Returns the pufETH -> ETH exchange rate. 10**18 represents exchange rate of 1
     */
    function getPufETHtoETHExchangeRate() external view returns (uint256);

    /**
     * @notice Creates a pod's {Safe} multisig wallet
     * @param safeProxyFactory Address of the {Safe} proxy factory
     * @param safeImplementation Address of the {Safe} implementation contract
     * @param podEnclavePubKeys Pod's encalve public keys
     * @param podWallets Pod's wallet addresses
     * @param mrenclave Unique enclave identifier
     */
    function createPodAccount(
        address safeProxyFactory,
        address safeImplementation,
        bytes[] calldata podEnclavePubKeys,
        address[] calldata podWallets,
        bytes32 mrenclave,
        bytes calldata emptyData
    ) external returns (Safe account);

    /**
     * @notice Creates a guardian {Safe} multisig wallet
     * @param safeProxyFactory Address of the {Safe} proxy factory
     * @param safeImplementation Address of the {Safe} implementation contract
     * @param guardiansEnclavePubKeys Guardian's encalve public keys
     * @param guardiansWallets Guardian's wallet addresses
     * @param mrenclave Unique enclave identifier
     */
    function createGuardianAccount(
        address safeProxyFactory,
        address safeImplementation,
        bytes[] calldata guardiansEnclavePubKeys,
        address[] calldata guardiansWallets,
        bytes32 mrenclave,
        bytes calldata emptyData
    ) external returns (Safe account);

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
