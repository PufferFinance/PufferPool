// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import { PufferModuleManager } from "puffer/PufferModuleManager.sol";
import { ERC1967Proxy } from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { GuardianModule } from "../src/GuardianModule.sol";
import { EnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { PufferOracleV2 } from "puffer/PufferOracleV2.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { RestakingOperator } from "puffer/RestakingOperator.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { IPufferOracle } from "pufETH/interface/IPufferOracle.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { NoImplementation } from "pufETH/NoImplementation.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { IDelayedWithdrawalRouter } from "eigenlayer/interfaces/IDelayedWithdrawalRouter.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { PufferVaultV2 } from "pufETH/PufferVaultV2.sol";
import { PufferDepositor } from "pufETH/PufferDepositor.sol";
import { PufferProtocolDeployment } from "./DeploymentStructs.sol";
import { GenerateOracleCalldata } from "script/GenerateOracleCalldata.s.sol";
import { OperationsCoordinator } from "puffer/OperationsCoordinator.sol";

/**
 * // Check that the simulation
 * add --slow if deploying to a mainnet fork like tenderly (its buggy sometimes)
 *
 *       forge script script/DeployOracleFix.s.sol:DeployOracleFix --rpc-url=$RPC_URL --private-key $PK --vvvv
 *
 *       `forge cache clean`
 *       forge script script/DeployOracleFix.s.sol:DeployOracleFix --rpc-url=$RPC_URL --private-key $PK --broadcast
 */
contract DeployOracleFix is Script {
    UpgradeableBeacon pufferModuleBeacon;
    UpgradeableBeacon restakingOperatorBeacon;
    EnclaveVerifier verifier;
    PufferModuleManager moduleManagerImplementation;
    PufferProtocol pufferProtocolImplementation;
    AccessManager accessManager;
    ERC1967Proxy pufferProtocolProxy;
    PufferModule moduleImplementation;
    RestakingOperator restakingOperatorImplementation;
    PufferOracleV2 oracle;
    OperationsCoordinator operationsCoordinator;
    PufferProtocol pufferProtocol;

    PufferVaultV2 pufferVaultV2Implementation;
    PufferDepositor pufferDepositorV2Implementation;

    ValidatorTicket validatorTicketImplementation;
    ERC1967Proxy validatorTicketProxy = ERC1967Proxy(payable(0x7D26AD6F6BA9D6bA1de0218Ae5e20CD3a273a55A));

    // Lido
    address ST_ETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    address LIDO_WITHDRAWAL_QUEUE = 0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1;

    address WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address BEACON_DEPOSIT_CONTRACT = 0x00000000219ab540356cBB839Cbe05303d7705Fa;

    // EigenLayer
    address EIGEN_POD_MANAGER = 0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338;
    address DELAYED_WITHDRAWAL_ROUTER = 0x7Fe7E9CC0F274d2435AD5d56D5fa73E47F6A23D8;
    address DELEGATION_MANAGER = 0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A;
    address EIGEN_SLASHER = 0xD92145c07f8Ed1D392c1B88017934E301CC1c3Cd;
    address STETH_STRATEGY = 0x93c4b944D05dfe6df7645A86cd2206016c51564D;
    address EIGEN_STRATEGY_MANAGER = 0x858646372CC42E1A627fcE94aa7A7033e7CF075A;

    // Existing Puffer
    address ACCESS_MANAGER = 0x8c1686069474410E6243425f4a10177a94EBEE11;
    address PUFFER_VAULT = 0xD9A442856C234a39a81a089C06451EBAa4306a72;
    address PUFFER_DEPOSITOR = 0x4aA799C5dfc01ee7d790e3bf1a7C2257CE1DcefF;
    address TIMELOCK = 0x3C28B7c7Ba1A1f55c9Ce66b263B33B204f2126eA;
    address DAO_MULTISIG = 0xC0896ab1A8cae8c2C1d27d011eb955Cca955580d; // Operations Multisig until the DAO is deployed

    // deployment parameters
    uint256 FRESHNESS_BLOCKS = 100; // This translates to 20 minutes
    address TREASURY = 0x946Ae7b21de3B0793Bb469e263517481B74A6950; // Safe multisig
    uint256 BPS_TREASURY_FEE_RATE = 200; // 2%
    uint256 BPS_GUARDIANS_FEE_RATE = 50; // 0.5%

    uint256 THRESHOLD = 1;
    address GUARDIAN_1 = 0x65d2dd7A66a2733a36559fE900A236280A05FBD6; // guardian1/paymaster
    address PAYMASTER = 0x65d2dd7A66a2733a36559fE900A236280A05FBD6; // Paymaster

    uint256 BPS_VT_UPDATE_PRICE_TOLERANCE = 500; // 5%

    GuardianModule module = GuardianModule(payable(0x628b183F248a142A598AA2dcCCD6f7E480a7CcF2));
    address validatorTicketAddress = 0x7D26AD6F6BA9D6bA1de0218Ae5e20CD3a273a55A;
    address moduleManagerProxy = 0x9E1E4fCb49931df5743e659ad910d331735C3860;

    function run() public {
        accessManager = AccessManager(ACCESS_MANAGER);

        // =================================== DOUBLE CHECK GUARDIANS ===================================
        address[] memory guardians = new address[](1);
        guardians[0] = GUARDIAN_1;

        vm.startBroadcast();

        // PufferOracle
        oracle = new PufferOracleV2(module, payable(PUFFER_VAULT), address(accessManager));

        operationsCoordinator =
            new OperationsCoordinator(PufferOracleV2(oracle), address(accessManager), BPS_VT_UPDATE_PRICE_TOLERANCE);

        //@todo QUEUE upgrade on multisig
        validatorTicketImplementation = new ValidatorTicket({
            guardianModule: payable(address(module)),
            treasury: payable(TREASURY),
            pufferVault: payable(PUFFER_VAULT),
            pufferOracle: IPufferOracle(address(oracle))
        });

        //@todo QUEUE upgrade on multisig
        pufferProtocolImplementation = new PufferProtocol({
            pufferVault: PufferVaultV2(payable(PUFFER_VAULT)),
            validatorTicket: ValidatorTicket(address(validatorTicketAddress)),
            guardianModule: module,
            moduleManager: moduleManagerProxy,
            oracle: oracle,
            beaconDepositContract: BEACON_DEPOSIT_CONTRACT
        });

        //@todo add the vault

        _sanityCheck();
        _writeJSON();

        new GenerateOracleCalldata().run({ oracle: address(oracle), coordinator: address(operationsCoordinator) });
    }

    function _writeJSON() internal {
        string memory obj = "";

        vm.serializeAddress(obj, "enclaveVerifier", address(verifier));
        vm.serializeAddress(obj, "guardianModule", address(module));
        vm.serializeAddress(obj, "oracle", address(oracle));
        vm.serializeAddress(obj, "validatorTicketProxy", address(validatorTicketProxy));
        vm.serializeAddress(obj, "validatorTicketImplementation", address(validatorTicketImplementation));
        vm.serializeAddress(obj, "pufferProtocolProxy", address(pufferProtocolProxy));
        vm.serializeAddress(obj, "pufferProtocolImplementation", address(pufferProtocolImplementation));
        vm.serializeAddress(obj, "moduleManagerProxy", address(moduleManagerProxy));
        vm.serializeAddress(obj, "moduleManagerImplementation", address(moduleManagerImplementation));
        vm.serializeAddress(obj, "pufferModuleBeacon", address(pufferModuleBeacon));
        vm.serializeAddress(obj, "pufferModuleImplementation", address(moduleImplementation));
        vm.serializeAddress(obj, "restakingOperatorBeacon", address(restakingOperatorBeacon));
        vm.serializeAddress(obj, "restakingOperatorImplementation", address(restakingOperatorImplementation));

        string memory finalJson = vm.serializeString(obj, "", "");
        vm.writeJson(finalJson, "./output/protocol-mainnet-fix.json");
    }

    function _sanityCheck() internal view {
        require(validatorTicketImplementation.TREASURY() == TREASURY, "treasury");
        require(address(validatorTicketImplementation.PUFFER_ORACLE()) == address(oracle), "oracle");
    }
}
