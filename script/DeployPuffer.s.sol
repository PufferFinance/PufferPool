// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferModuleManager } from "puffer/PufferModuleManager.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { NoImplementation } from "pufETH/NoImplementation.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { RestakingOperator } from "puffer/RestakingOperator.sol";
import { ERC1967Proxy } from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { EigenPodManagerMock } from "../test/mocks/EigenPodManagerMock.sol";
import { DelegationManagerMock } from "../test/mocks/DelegationManagerMock.sol";
import { BeaconMock } from "../test/mocks/BeaconMock.sol";
import { IDelayedWithdrawalRouter } from "eigenlayer/interfaces/IDelayedWithdrawalRouter.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { ISlasher } from "eigenlayer/interfaces/ISlasher.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { PufferVaultV2 } from "pufETH/PufferVaultV2.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { GuardiansDeployment, PufferProtocolDeployment } from "./DeploymentStructs.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { ExecutionCoordinator } from "puffer/ExecutionCoordinator.sol";
import { PufferOracleV2 } from "puffer/PufferOracleV2.sol";
import { IPufferOracleV2 } from "puffer/interface/IPufferOracleV2.sol";

/**
 * @title DeployPuffer
 * @author Puffer Finance
 * @notice Deploys PufferProtocol Contracts
 * @dev
 *
 *
 *         NOTE:
 *
 *         If you ran the deployment script, but did not `--broadcast` the transaction, it will still update your local chainId-deployment.json file.
 *         Other scripts will fail because addresses will be updated in deployments file, but the deployment never happened.
 *
 *
 *         forge script script/DeployPuffer.s.sol:DeployPuffer -vvvv --rpc-url=$EPHEMERY_RPC_URL --broadcast
 */
contract DeployPuffer is BaseScript {
    PufferProtocol pufferProtocolImpl;
    AccessManager accessManager;
    ERC1967Proxy proxy;
    ERC1967Proxy validatorTicketProxy;
    ERC1967Proxy moduleManagerProxy;
    PufferProtocol pufferProtocol;
    UpgradeableBeacon pufferModuleBeacon;
    UpgradeableBeacon restakingOperatorBeacon;
    PufferModuleManager moduleManager;
    ExecutionCoordinator priceValidator;

    address eigenPodManager;
    address delayedWithdrawalRouter;
    address delegationManager;
    address eigenSlasher;
    address treasury;

    function run(GuardiansDeployment calldata guardiansDeployment, address pufferVault, address oracle)
        public
        broadcast
        returns (PufferProtocolDeployment memory)
    {
        accessManager = AccessManager(guardiansDeployment.accessManager);

        if (isMainnet()) {
            // Mainnet / Mainnet fork
            eigenPodManager = 0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338;
            delayedWithdrawalRouter = 0x7Fe7E9CC0F274d2435AD5d56D5fa73E47F6A23D8;
            delegationManager = 0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A;
            eigenSlasher = 0xD92145c07f8Ed1D392c1B88017934E301CC1c3Cd;
            treasury = vm.envAddress("TREASURY");
        } else if (isAnvil()) {
            // Local chain / tests
            eigenPodManager = address(new EigenPodManagerMock());
            delayedWithdrawalRouter = address(0);
            delegationManager = address(new DelegationManagerMock());
            eigenSlasher = vm.envOr("EIGEN_SLASHER", address(1)); //@todo
            treasury = address(1);
        } else {
            // Holesky
            eigenPodManager = 0x30770d7E3e71112d7A6b7259542D1f680a70e315;
            delayedWithdrawalRouter = 0x642c646053eaf2254f088e9019ACD73d9AE0FA32;
            delegationManager = 0xA44151489861Fe9e3055d95adC98FbD462B948e7;
            eigenSlasher = 0xcAe751b75833ef09627549868A04E32679386e7C;
            treasury = 0x61A44645326846F9b5d9c6f91AD27C3aD28EA390;
        }

        priceValidator = new ExecutionCoordinator(PufferOracleV2(oracle), address(accessManager), 500); // 500 BPS = 5%

        validatorTicketProxy = new ERC1967Proxy(address(new NoImplementation()), "");
        ValidatorTicket validatorTicketImplementation = new ValidatorTicket({
            guardianModule: payable(guardiansDeployment.guardianModule),
            treasury: payable(treasury),
            pufferVault: payable(pufferVault),
            pufferOracle: IPufferOracleV2(oracle)
        });

        NoImplementation(payable(address(validatorTicketProxy))).upgradeToAndCall(
            address(validatorTicketImplementation),
            abi.encodeCall(
                ValidatorTicket.initialize,
                (address(accessManager), 500, 50) //@todo recheck 5% treasury, 0.5% guardians
            )
        );

        // UUPS proxy for PufferProtocol
        proxy = new ERC1967Proxy(address(new NoImplementation()), "");
        {
            // Deploy empty proxy for PufferModuleManager
            // We need it to have it as immutable in PufferModule
            moduleManagerProxy = new ERC1967Proxy(address(new NoImplementation()), "");

            PufferModule moduleImplementation = new PufferModule({
                protocol: PufferProtocol(payable(proxy)),
                eigenPodManager: eigenPodManager,
                eigenWithdrawalRouter: IDelayedWithdrawalRouter(delayedWithdrawalRouter),
                delegationManager: IDelegationManager(delegationManager),
                moduleManager: PufferModuleManager(address(moduleManagerProxy))
            });
            vm.label(address(moduleImplementation), "PufferModuleImplementation");

            RestakingOperator restakingOperatorImplementation = new RestakingOperator(
                IDelegationManager(delegationManager),
                ISlasher(eigenSlasher),
                PufferModuleManager(address(moduleManagerProxy))
            );

            pufferModuleBeacon = new UpgradeableBeacon(address(moduleImplementation), address(accessManager));
            restakingOperatorBeacon =
                new UpgradeableBeacon(address(restakingOperatorImplementation), address(accessManager));

            moduleManager = new PufferModuleManager({
                pufferModuleBeacon: address(pufferModuleBeacon),
                restakingOperatorBeacon: address(restakingOperatorBeacon),
                pufferProtocol: address(proxy)
            });

            // Puffer Service implementation
            pufferProtocolImpl = new PufferProtocol({
                pufferVault: PufferVaultV2(payable(pufferVault)),
                validatorTicket: ValidatorTicket(address(validatorTicketProxy)),
                guardianModule: GuardianModule(payable(guardiansDeployment.guardianModule)),
                moduleManager: address(moduleManagerProxy),
                oracle: IPufferOracleV2(oracle),
                beaconDepositContract: getStakingContract()
            });
        }
        NoImplementation(payable(address(moduleManagerProxy))).upgradeToAndCall(
            address(moduleManager), abi.encodeCall(moduleManager.initialize, (address(accessManager)))
        );

        pufferProtocol = PufferProtocol(payable(address(proxy)));

        NoImplementation(payable(address(proxy))).upgradeToAndCall(address(pufferProtocolImpl), "");

        // Initialize the Pool
        pufferProtocol.initialize({ accessManager: address(accessManager) });

        vm.label(address(accessManager), "AccessManager");
        vm.label(address(priceValidator), "executionCoordinator");
        vm.label(address(validatorTicketProxy), "ValidatorTicketProxy");
        vm.label(address(validatorTicketImplementation), "ValidatorTicketImplementation");
        vm.label(address(proxy), "PufferProtocolProxy");
        vm.label(address(pufferProtocolImpl), "PufferProtocolImplementation");
        vm.label(address(moduleManagerProxy), "PufferModuleManager");
        vm.label(address(pufferModuleBeacon), "PufferModuleBeacon");
        vm.label(address(guardiansDeployment.enclaveVerifier), "EnclaveVerifier");
        vm.label(address(guardiansDeployment.enclaveVerifier), "EnclaveVerifier");

        // return (pufferProtocol, pool, accessManager);
        return PufferProtocolDeployment({
            validatorTicket: address(validatorTicketProxy),
            pufferProtocolImplementation: address(pufferProtocolImpl),
            pufferProtocol: address(proxy),
            guardianModule: guardiansDeployment.guardianModule,
            accessManager: guardiansDeployment.accessManager,
            enclaveVerifier: guardiansDeployment.enclaveVerifier,
            beacon: address(pufferModuleBeacon),
            restakingOperatorBeacon: address(restakingOperatorBeacon),
            moduleManager: address(moduleManagerProxy),
            pufferOracle: address(oracle),
            executionCoordinator: address(priceValidator),
            timelock: address(0), // overwritten in DeployEverything
            stETH: address(0), // overwritten in DeployEverything
            pufferVault: address(0), // overwritten in DeployEverything
            pufferDepositor: address(0), // overwritten in DeployEverything
            weth: address(0) // overwritten in DeployEverything
         });
    }

    function getStakingContract() internal returns (address) {
        // Mainnet
        if (isMainnet()) {
            return 0x00000000219ab540356cBB839Cbe05303d7705Fa;
        }

        // Goerli
        if (block.chainid == 5) {
            return 0xff50ed3d0ec03aC01D4C79aAd74928BFF48a7b2b;
        }

        // Holesky
        if (block.chainid == 17000) {
            return 0x4242424242424242424242424242424242424242;
        }

        // Tests / local chain
        if (isAnvil()) {
            return address(new BeaconMock());
        }

        // Ephemery
        return 0x4242424242424242424242424242424242424242;
    }
}
