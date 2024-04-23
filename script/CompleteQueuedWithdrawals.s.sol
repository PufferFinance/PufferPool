// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";
import { IERC20 } from "openzeppelin/token/ERC20/IERC20.sol";
import { PufferModuleManager } from "puffer/PufferModuleManager.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";

/**
 * @dev Example on how to run the script
 *
 *      Holesky Example CompleteQueuedWithdrawals
 *      https://holesky.etherscan.io/tx/0x6b77f85ba3024670499d74d3d900596e9b9d5231ed3f8b2506d68f6ec6673b09
 *
 *      forge script script/CompleteQueuedWithdrawals.s.sol:CompleteQueuedWithdrawals --rpc-url=$RPC_URL --sig "run(address,bytes32,address,address[],uint256[],uint32[],uint256[])" "0xe4695ab93163F91665Ce5b96527408336f070a71" "0x5055464645525f4d4f44554c455f300000000000000000000000000000000000" "0x0b0456ec773b7d89c9decc38b682f98556cf9862" "[0x0000000000000000000000000000000000000000]" "[1]" "[1375996]" "[31998517520000000000]" --broadcast --private-key=$PK
 */
contract CompleteQueuedWithdrawals is Script {
    address public BEACON_CHAIN_STRATEGY = 0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0;

    function run(
        address pufferModuleManager,
        bytes32 moduleName,
        address pufferModule,
        address[] calldata delegatedTo,
        uint256[] calldata nonces,
        uint32[] calldata startBlocks,
        uint256[] calldata sharesToWithdraw,
        bool[] calldata receiveAsTokens
    ) external {
        IDelegationManager.Withdrawal[] memory withdrawals = new IDelegationManager.Withdrawal[](nonces.length);

        // Withdrawal data can be fetched from the transaction logs, for example:
        // cast run 0x3fecf92f659089b796922a11271e713bc97040f1a21b2671274577d4b294c5b9 --rpc-url=$HOLESKY_RPC_URL --verbose

        // Get validator fields and proofs
        for (uint256 i = 0; i < nonces.length; ++i) {
            uint256[] memory shares = new uint256[](1);
            shares[0] = sharesToWithdraw[i];

            IStrategy[] memory strategies = new IStrategy[](1);
            strategies[0] = IStrategy(BEACON_CHAIN_STRATEGY);

            withdrawals[i] = IDelegationManager.Withdrawal({
                staker: pufferModule,
                delegatedTo: delegatedTo[i],
                withdrawer: pufferModule,
                nonce: nonces[i],
                startBlock: startBlocks[i],
                strategies: strategies,
                shares: shares
            });
        }

        IERC20[] memory t = new IERC20[](1);
        t[0] = IERC20(BEACON_CHAIN_STRATEGY);

        IERC20[][] memory tokens = new IERC20[][](1);
        tokens[0] = t;
        uint256[] memory middlewareTimesIndexes = new uint256[](1); // 0

        vm.startBroadcast();
        PufferModuleManager(pufferModuleManager).callCompleteQueuedWithdrawals({
            moduleName: moduleName,
            withdrawals: withdrawals,
            tokens: tokens,
            middlewareTimesIndexes: middlewareTimesIndexes,
            receiveAsTokens: receiveAsTokens
        });
    }
}
