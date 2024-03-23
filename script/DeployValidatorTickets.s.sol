// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import { ERC1967Proxy } from "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { GuardianModule } from "../src/GuardianModule.sol";
import { EnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { PufferOracle } from "puffer/PufferOracle.sol";
import { AccessManager } from "openzeppelin/access/manager/AccessManager.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { IPufferOracle } from "pufETH/interface/IPufferOracle.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";

/**
 * forge script script/DeployValidatorTickets.s.sol:DeployValidatorTickets --rpc-url=$RPC_URL --private-key $PK
 */
contract DeployValidatorTickets is Script {
    EnclaveVerifier verifier;
    GuardianModule module;
    AccessManager accessManager;

    //@todo DOUBLE CHECK THESE VALUES
    // existing values
    address ACCESS_MANAGER = 0x8c1686069474410E6243425f4a10177a94EBEE11;
    address PUFFER_VAULT = 0xD9A442856C234a39a81a089C06451EBAa4306a72;

    // deployment parameters
    uint256 FRESHNESS_BLOCKS = 300;
    uint256 THRESHOLD = 1;
    address TREASURY = 0xDDDeAfB492752FC64220ddB3E7C9f1d5CcCdFdF0;
    uint256 TREASURY_FEE_RATE = 500; // 5%
    uint256 GUARDIANS_FEE_RATE = 50; // 0.5%

    function run() public {
        accessManager = AccessManager(ACCESS_MANAGER);

        //@todo =================================== CHECK GUARDIANS ===================================
        address[] memory guardians = new address[](1);
        guardians[0] = TREASURY;

        verifier = new EnclaveVerifier(FRESHNESS_BLOCKS, address(accessManager));
        module = new GuardianModule(verifier, guardians, THRESHOLD, address(accessManager));

        PufferOracle oracle = new PufferOracle(address(accessManager));

        ValidatorTicket validatorTicketImplementation = new ValidatorTicket({
            guardianModule: payable(address(module)),
            treasury: payable(TREASURY),
            pufferVault: payable(PUFFER_VAULT),
            pufferOracle: IPufferOracle(address(oracle))
        });

        ERC1967Proxy validatorTicketProxy = new ERC1967Proxy(
            address(validatorTicketImplementation),
            abi.encodeCall(ValidatorTicket.initialize, (address(accessManager), TREASURY_FEE_RATE, GUARDIANS_FEE_RATE))
        );

        _sanityCheck(ValidatorTicket(address(validatorTicketProxy)), address(oracle), address(module));

        string memory obj = "";

        vm.serializeAddress(obj, "validatorTicketProxy", address(validatorTicketProxy));
        vm.serializeAddress(obj, "guardianModule", address(module));
        vm.serializeAddress(obj, "enclaveVerifier", address(verifier));
        vm.serializeAddress(obj, "validatorTicketImplementation", address(validatorTicketImplementation));

        string memory finalJson = vm.serializeString(obj, "", "");
        vm.writeJson(finalJson, "./output/validator-ticket-deployment.json");
    }

    function _sanityCheck(ValidatorTicket vt, address oracle, address guardianModule) internal view {
        require(vt.TREASURY() == TREASURY, "treasury");
        require(vt.GUARDIAN_MODULE() == guardianModule, "guardian module");
        require(vt.PUFFER_VAULT() == PUFFER_VAULT, "vault");
        require(address(vt.PUFFER_ORACLE()) == oracle, "oracle");
        require(vt.getProtocolFeeRate() == 500, "protocol fee rate");
    }
}
