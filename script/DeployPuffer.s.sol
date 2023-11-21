// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { WithdrawalPool } from "puffer/WithdrawalPool.sol";
import { PufferStrategy } from "puffer/PufferStrategy.sol";
import { NoRestakingStrategy } from "puffer/NoRestakingStrategy.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { ERC1967Proxy } from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { EigenPodManagerMock } from "../test/mocks/EigenPodManagerMock.sol";
import { BeaconMock } from "../test/mocks/BeaconMock.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { Strings } from "openzeppelin/utils/Strings.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { UpgradeableBeacon } from "openzeppelin/proxy/beacon/UpgradeableBeacon.sol";

/**
 * @title DeployPuffer
 * @author Puffer finance
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
    function run() public broadcast returns (PufferProtocol, PufferPool, AccessManager) {
        string memory guardiansDeployment =
            vm.readFile(string.concat("./output/", Strings.toString(block.chainid), "-guardians.json"));
        string memory obj = "";

        PufferProtocol pufferProtocolImpl;

        AccessManager accessManager = AccessManager(stdJson.readAddress(guardiansDeployment, ".accessManager"));

        {
            // PufferTreasury
            address payable treasury = payable(vm.envOr("TREASURY", address(1337)));
            address payable guardians = payable(stdJson.readAddress(guardiansDeployment, ".guardians"));

            address eigenPodManager = vm.envOr("EIGENPOD_MANAGER", address(new EigenPodManagerMock()));

            PufferStrategy strategyImplementation = new PufferStrategy(IEigenPodManager(eigenPodManager));

            UpgradeableBeacon beacon = new UpgradeableBeacon(address(strategyImplementation), address(accessManager));
            vm.serializeAddress(obj, "PufferStrategyBeacon", address(beacon));

            // Puffer Service implementation
            pufferProtocolImpl =
                new PufferProtocol({guardians: Safe(guardians), treasury: treasury, strategyBeacon: address(beacon)});
        }

        // UUPS proxy for PufferProtocol
        ERC1967Proxy proxy = new ERC1967Proxy(address(pufferProtocolImpl), "");

        PufferProtocol pufferProtocol = PufferProtocol(payable(address(proxy)));
        // Deploy pool
        PufferPool pool = new PufferPool(pufferProtocol, address(accessManager));

        WithdrawalPool withdrawalPool = new WithdrawalPool(pool, address(accessManager));

        // Read guardians module variable
        address payable guardiansModule = payable(stdJson.readAddress(guardiansDeployment, ".guardianModule"));

        NoRestakingStrategy noRestaking =
            new NoRestakingStrategy(address(accessManager), pufferProtocol, getStakingContract());

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

        // Initialize the Pool
        pufferProtocol.initialize({
            accessManager: address(accessManager),
            pool: pool,
            withdrawalPool: withdrawalPool,
            guardianSafeModule: guardiansModule,
            noRestakingStrategy: address(noRestaking),
            smoothingCommitments: smoothingCommitments
        });

        vm.serializeAddress(obj, "PufferProtocolImplementation", address(pufferProtocolImpl));
        vm.serializeAddress(obj, "noRestakingStrategy", address(noRestaking));
        vm.serializeAddress(obj, "pufferPool", address(pool));
        vm.serializeAddress(obj, "withdrawalPool", address(withdrawalPool));
        vm.serializeAddress(obj, "PufferProtocol", address(proxy));

        string memory finalJson = vm.serializeString(obj, "", "");

        vm.writeJson(finalJson, "./output/puffer.json");

        return (pufferProtocol, pool, accessManager);
    }

    function getStakingContract() internal returns (address) {
        // Mainnet
        if (block.chainid == 1) {
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
        if (block.chainid == 31337) {
            return address(new BeaconMock());
        }

        // Ephemery
        return 0x4242424242424242424242424242424242424242;
    }
}
