// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @notice Guardians deployment struct
 */
struct GuardiansDeployment {
    address accessManager;
    address guardianModule;
    address enclaveVerifier;
}

/**
 * @notice PufferProtocolDeployment
 */
struct PufferProtocolDeployment {
    address pufferProtocolImplementation;
    address pufferProtocol;
    address guardianModule;
    address accessManager;
    address enclaveVerifier;
    address beacon; // Beacon for Puffer modules
    address restakingOperatorBeacon; // Beacon for Restaking Operator
    address moduleManager;
    address validatorTicket;
    address pufferOracle;
    address VTpriceValidator;
    address pufferDepositor; // from pufETH repository (dependency)
    address pufferVault; // from pufETH repository (dependency)
    address stETH; // from pufETH repository (dependency)
    address weth; // from pufETH repository (dependency)
    address timelock; // from pufETH repository (dependency)
}
