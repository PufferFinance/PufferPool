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
        bytes32 mrenclave
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
        bytes32 mrenclave
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

    // // LST related
    // function mint(address recipient) external payable;

    // function redeem(address recipient) external payable;

    // // Contract maintanence
    // function pause() external;

    // function resume() external;

    // function upgrade(address newContractAddr) external;

    // // Setters to set parameters
    // function setParamX() external;

    // // Getters to get parameters
    // function getParamX() external returns (uint256 X);
}
