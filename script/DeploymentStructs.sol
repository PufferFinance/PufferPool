// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @notice Guardians deployment struct
 */
struct GuardiansDeployment {
    address guardians;
    address accessManager;
    address guardianModule;
    address safeProxyFactory;
    address safeImplementation;
    address enclaveVerifier;
    address pauser;
}

/**
 * @notice PufferDeployment
 */
struct PufferDeployment {
    address pufferProtocolImplementation;
    address noRestakingStrategy;
    address pufferPool;
    address withdrawalPool;
    address pufferProtocol;
    address guardianModule;
    address guardians;
    address accessManager;
    address enclaveVerifier;
    address pauser;
    address beacon; // Beacon for Puffer strategies
}
