// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @notice Guardians deployment struct
 */
struct GuardiansDeployment {
    address accessManager;
    address guardianModule;
    address enclaveVerifier;
    address pauser;
}

/**
 * @notice PufferDeployment
 */
struct PufferDeployment {
    address pufferProtocolImplementation;
    address NoRestakingModule;
    address pufferPool;
    address withdrawalPool;
    address pufferProtocol;
    address guardianModule;
    address accessManager;
    address enclaveVerifier;
    address pauser;
    address beacon; // Beacon for Puffer modules
    address moduleFactory;
}
