// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferModuleFactory } from "puffer/PufferModuleFactory.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { NoImplementation } from "pufETH/NoImplementation.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { NoRestakingModule } from "puffer/NoRestakingModule.sol";
import { ERC1967Proxy } from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { EigenPodManagerMock } from "../test/mocks/EigenPodManagerMock.sol";
import { DelegationManagerMock } from "../test/mocks/DelegationManagerMock.sol";
import { BeaconMock } from "../test/mocks/BeaconMock.sol";
import { IDelayedWithdrawalRouter } from "eigenlayer/interfaces/IDelayedWithdrawalRouter.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { PufferVaultV2 } from "pufETH/PufferVaultV2.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { GuardiansDeployment, PufferProtocolDeployment } from "./DeploymentStructs.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { IPufferOracleV2 } from "pufETH/interface/IPufferOracleV2.sol";

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
    PufferProtocol pufferProtocol;
    UpgradeableBeacon beacon;
    PufferModuleFactory moduleFactory;

    address eigenPodManager;
    address delayedWithdrawalRouter;
    address delegationManager;
    address treasury;

    function run(GuardiansDeployment calldata guardiansDeployment, address pufferVault, address weth, address oracle)
        public
        broadcast
        returns (PufferProtocolDeployment memory)
    {
        accessManager = AccessManager(guardiansDeployment.accessManager);

        if (isMainnet()) {
            // Mainnet / Mainnet fork
            eigenPodManager = vm.envAddress("EIGENPOD_MANAGER");
            delayedWithdrawalRouter = vm.envAddress("DELAYED_WITHDRAWAL_ROUTER");
            delegationManager = vm.envAddress("DELEGATION_MANAGER");
            treasury = vm.envAddress("TREASURY");
        } else if (isAnvil()) {
            // Local chain / tests
            eigenPodManager = address(new EigenPodManagerMock());
            delayedWithdrawalRouter = address(0);
            delegationManager = address(new DelegationManagerMock());
            treasury = address(1);
        } else {
            // Testnets
            eigenPodManager = vm.envOr("EIGENPOD_MANAGER", address(new EigenPodManagerMock()));
            delayedWithdrawalRouter = vm.envOr("DELAYED_WITHDRAWAL_ROUTER", address(0));
            delegationManager = vm.envOr("DELEGATION_MANAGER", address(new DelegationManagerMock()));
            treasury = vm.envOr("TREASURY", 0x61A44645326846F9b5d9c6f91AD27C3aD28EA390); // Holesky Safe
        }

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
            PufferModule moduleImplementation = new PufferModule(
                PufferProtocol(payable(proxy)),
                eigenPodManager,
                IDelayedWithdrawalRouter(delayedWithdrawalRouter),
                IDelegationManager(delegationManager)
            );
            vm.label(address(moduleImplementation), "PufferModuleImplementation");

            beacon = new UpgradeableBeacon(address(moduleImplementation), address(accessManager));

            moduleFactory = new PufferModuleFactory({
                beacon: address(beacon),
                pufferProtocol: address(proxy),
                authority: address(accessManager)
            });

            // Puffer Service implementation
            pufferProtocolImpl = new PufferProtocol({
                pufferVault: PufferVaultV2(payable(pufferVault)),
                validatorTicket: ValidatorTicket(address(validatorTicketProxy)),
                guardianModule: GuardianModule(payable(guardiansDeployment.guardianModule)),
                moduleFactory: address(moduleFactory),
                oracle: IPufferOracleV2(oracle)
            });
        }

        pufferProtocol = PufferProtocol(payable(address(proxy)));

        NoRestakingModule noRestaking =
            new NoRestakingModule(address(accessManager), pufferProtocol, getStakingContract(), bytes32("NO_RESTAKING"));

        NoImplementation(payable(address(proxy))).upgradeToAndCall(address(pufferProtocolImpl), "");

        // Initialize the Pool
        pufferProtocol.initialize({ accessManager: address(accessManager), noRestakingModule: address(noRestaking) });

        vm.label(address(accessManager), "AccessManager");
        vm.label(address(validatorTicketProxy), "ValidatorTicketProxy");
        vm.label(address(validatorTicketImplementation), "ValidatorTicketImplementation");
        vm.label(address(proxy), "PufferProtocolProxy");
        vm.label(address(pufferProtocolImpl), "PufferProtocolImplementation");
        vm.label(address(moduleFactory), "PufferModuleFactory");
        vm.label(address(beacon), "PufferModuleBeacon");
        vm.label(address(guardiansDeployment.enclaveVerifier), "EnclaveVerifier");
        vm.label(address(guardiansDeployment.enclaveVerifier), "EnclaveVerifier");

        // return (pufferProtocol, pool, accessManager);
        return PufferProtocolDeployment({
            validatorTicket: address(validatorTicketProxy),
            pufferProtocolImplementation: address(pufferProtocolImpl),
            NoRestakingModule: address(noRestaking),
            pufferProtocol: address(proxy),
            guardianModule: guardiansDeployment.guardianModule,
            accessManager: guardiansDeployment.accessManager,
            enclaveVerifier: guardiansDeployment.enclaveVerifier,
            beacon: address(beacon),
            moduleFactory: address(moduleFactory),
            pufferOracle: address(oracle),
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
