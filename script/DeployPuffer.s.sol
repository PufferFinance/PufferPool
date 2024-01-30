// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { PufferModuleFactory } from "puffer/PufferModuleFactory.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { NoImplementation } from "puffer/NoImplementation.sol";
import { PufferModule } from "puffer/PufferModule.sol";
import { NoRestakingModule } from "puffer/NoRestakingModule.sol";
import { ERC1967Proxy } from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { EigenPodManagerMock } from "../test/mocks/EigenPodManagerMock.sol";
import { DelegationManagerMock } from "../test/mocks/DelegationManagerMock.sol";
import { BeaconMock } from "../test/mocks/BeaconMock.sol";
import { IDelayedWithdrawalRouter } from "eigenlayer/interfaces/IDelayedWithdrawalRouter.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";
import { GuardiansDeployment, PufferDeployment } from "./DeploymentStructs.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";

/**
 * @title DeployPuffer
 * @author Puffer Finance
 * @notice Deploys PufferPool Contracts
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
    PufferProtocol pufferProtocol;
    PufferPool pool;
    WithdrawalPool withdrawalPool;
    UpgradeableBeacon beacon;
    PufferModuleFactory moduleFactory;
    ERC1967Proxy validatorTicketProxy;

    address payable treasury;

    address eigenPodManager;
    address delayedWithdrawalRouter;
    address delegationManager;

    function run(GuardiansDeployment calldata guardiansDeployment) public broadcast returns (PufferDeployment memory) {
        string memory obj = "";

        accessManager = AccessManager(guardiansDeployment.accessManager);
        bytes32 poolSalt = bytes32("pufferPool");
        bytes32 withdrawalPoolSalt = bytes32("withdrawalPool");

        if (isMainnet()) {
            // Mainnet / Mainnet fork
            treasury = payable(vm.envAddress("TREASURY"));
            eigenPodManager = vm.envAddress("EIGENPOD_MANAGER");
            delayedWithdrawalRouter = vm.envAddress("DELAYED_WITHDRAWAL_ROUTER");
            delegationManager = vm.envAddress("DELEGATION_MANAGER");
        } else if (isAnvil()) {
            // Local chain / tests
            treasury = payable(address(1337));
            eigenPodManager = address(new EigenPodManagerMock());
            delayedWithdrawalRouter = address(0);
            delegationManager = address(new DelegationManagerMock());
        } else {
            // Testnets
            treasury = payable(vm.envOr("TREASURY", address(1337)));
            eigenPodManager = vm.envOr("EIGENPOD_MANAGER", address(new EigenPodManagerMock()));
            delayedWithdrawalRouter = vm.envOr("DELAYED_WITHDRAWAL_ROUTER", address(0));
            delegationManager = vm.envOr("DELEGATION_MANAGER", address(new DelegationManagerMock()));
        }

        validatorTicketProxy = new ERC1967Proxy(address(new NoImplementation()), "");
        ValidatorTicket validatorTicketImplementation = new ValidatorTicket();

        NoImplementation(payable(address(validatorTicketProxy))).upgradeToAndCall(
            address(validatorTicketImplementation),
            abi.encodeCall(
                ValidatorTicket.initialize,
                (address(accessManager), address(1), payable(address(2)), payable(address(3)), payable(address(4)), 90*10**18, 10*10**18)
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
            vm.serializeAddress(obj, "moduleBeacon", address(beacon));

            // Predict Pool address
            address predictedPool = computeCreate2Address(
                poolSalt, hashInitCode(type(PufferPool).creationCode, abi.encode(proxy, address(accessManager)))
            );

            // Predict Withdrawal pool address
            address predictedWithdrawalPool = computeCreate2Address(
                withdrawalPoolSalt,
                hashInitCode(type(WithdrawalPool).creationCode, abi.encode(predictedPool, address(accessManager)))
            );

            moduleFactory = new PufferModuleFactory({
                beacon: address(beacon),
                pufferProtocol: address(proxy),
                authority: address(accessManager)
            });

            // Puffer Service implementation
            pufferProtocolImpl = new PufferProtocol({
                withdrawalPool: WithdrawalPool(payable(predictedWithdrawalPool)),
                pool: PufferPool(payable(predictedPool)),
                validatorTicket: ValidatorTicket(address(validatorTicketProxy)),
                guardianModule: GuardianModule(payable(guardiansDeployment.guardianModule)),
                treasury: treasury,
                moduleFactory: address(moduleFactory)
            });
        }

        pufferProtocol = PufferProtocol(payable(address(proxy)));
        // Deploy pool
        pool = new PufferPool{ salt: poolSalt }(pufferProtocol, address(accessManager));

        withdrawalPool = new WithdrawalPool{ salt: withdrawalPoolSalt }(pool, address(accessManager));

        NoRestakingModule noRestaking =
            new NoRestakingModule(address(accessManager), pufferProtocol, getStakingContract(), bytes32("NO_RESTAKING"));

        uint256[] memory smoothingCommitments = new uint256[](14);

        smoothingCommitments[0] = 0.11995984289445429 ether;
        smoothingCommitments[1] = 0.11989208274022745 ether;
        smoothingCommitments[2] = 0.1197154447609346 ether;
        smoothingCommitments[3] = 0.11928478246786729 ether;
        smoothingCommitments[4] = 0.11838635147178002 ether;
        smoothingCommitments[5] = 0.11699999999999999 ether;
        smoothingCommitments[6] = 0.11561364852821997 ether;
        smoothingCommitments[7] = 0.11471521753213271 ether;
        smoothingCommitments[8] = 0.1142845552390654 ether;
        smoothingCommitments[9] = 0.11410791725977254 ether;
        smoothingCommitments[10] = 0.1140401571055457 ether;
        smoothingCommitments[11] = 0.11401483573893981 ether;
        smoothingCommitments[12] = 0.1140054663071664 ether;
        smoothingCommitments[13] = 0.1140020121007828 ether;

        NoImplementation(payable(address(proxy))).upgradeToAndCall(address(pufferProtocolImpl), "");

        // Initialize the Pool
        pufferProtocol.initialize({
            accessManager: address(accessManager),
            noRestakingModule: address(noRestaking),
            smoothingCommitments: smoothingCommitments
        });

        vm.label(address(accessManager), "AccessManager");
        vm.label(address(validatorTicketProxy), "ValidatorTicketProxy");
        vm.label(address(validatorTicketImplementation), "ValidatorTicketImplementation");
        vm.label(address(proxy), "PufferProtocolProxy");
        vm.label(address(pufferProtocolImpl), "PufferProtocolImplementation");
        vm.label(address(pool), "PufferPool");
        vm.label(address(withdrawalPool), "WithdrawalPool");
        vm.label(address(moduleFactory), "PufferModuleFactory");
        vm.label(address(beacon), "PufferModuleBeacon");
        vm.label(address(guardiansDeployment.enclaveVerifier), "EnclaveVerifier");
        vm.label(address(guardiansDeployment.enclaveVerifier), "EnclaveVerifier");
        vm.label(address(treasury), "treasury");

        vm.serializeAddress(obj, "PufferProtocolImplementation", address(pufferProtocolImpl));
        vm.serializeAddress(obj, "noRestakingModule", address(noRestaking));
        vm.serializeAddress(obj, "pufferPool", address(pool));
        vm.serializeAddress(obj, "withdrawalPool", address(withdrawalPool));
        vm.serializeAddress(obj, "PufferProtocol", address(proxy));
        vm.serializeAddress(obj, "moduleFactory", address(moduleFactory));
        vm.serializeAddress(obj, "guardianModule", guardiansDeployment.guardianModule);
        vm.serializeAddress(obj, "accessManager", guardiansDeployment.accessManager);
        vm.serializeAddress(obj, "treasury", address(treasury));

        string memory finalJson = vm.serializeString(obj, "", "");

        vm.writeJson(finalJson, "./output/puffer.json");
        // return (pufferProtocol, pool, accessManager);
        return PufferDeployment({
            pufferProtocolImplementation: address(pufferProtocolImpl),
            NoRestakingModule: address(noRestaking),
            pufferPool: address(pool),
            withdrawalPool: address(withdrawalPool),
            pufferProtocol: address(proxy),
            guardianModule: guardiansDeployment.guardianModule,
            accessManager: guardiansDeployment.accessManager,
            enclaveVerifier: guardiansDeployment.enclaveVerifier,
            pauser: guardiansDeployment.pauser,
            beacon: address(beacon),
            moduleFactory: address(moduleFactory),
            validatorTicket: address(validatorTicketProxy)
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
