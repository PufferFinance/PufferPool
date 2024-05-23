// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { Address } from "openzeppelin/utils/Address.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { IValidatorTicket } from "puffer/interface/IValidatorTicket.sol";
import { PufferOracle } from "puffer/PufferOracle.sol";
import { PufferOracleV2 } from "puffer/PufferOracleV2.sol";
import { ValidatorTicketPricer } from "puffer/ValidatorTicketPricer.sol";
import { ROLE_ID_OPERATIONS_PAYMASTER, ROLE_ID_OPERATIONS_MULTISIG } from "pufETHScript/Roles.sol";

/**
 * @dev This test is for the ValidatorTicket smart contract with `src/PufferOracle.sol`
 */
contract ValidatorTicketPricerTest is TestHelper {
    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();

        vm.prank(_broadcaster);
        accessManager.grantRole(ROLE_ID_OPERATIONS_PAYMASTER, address(this), 0);
    }

    function testSetDailyMevPayoutsChangeToleranceBps() public {
        uint16 newTolerance = 500; // 5%

        vm.prank(OPERATIONS_MULTISIG);
        validatorTicketPricer.setDailyMevPayoutsChangeToleranceBps(newTolerance);
        assertEq(validatorTicketPricer.getDailyMevPayoutsChangeToleranceBps(), newTolerance);
    }

    function testSetDailyConsensusRewardsChangeToleranceBps() public {
        uint16 newTolerance = 300; // 3%

        vm.prank(OPERATIONS_MULTISIG);
        validatorTicketPricer.setDailyConsensusRewardsChangeToleranceBps(newTolerance);
        assertEq(validatorTicketPricer.getDailyConsensusRewardsChangeToleranceBps(), newTolerance);
    }

    function testSetDiscountRate() public {
        uint16 newRate = 200; // 2%

        vm.prank(DAO);
        validatorTicketPricer.setDiscountRate(newRate);
        assertEq(validatorTicketPricer.getDiscountRateBps(), newRate);
    }

    function testSetDailyMevPayouts() public {
        vm.prank(_broadcaster);
        uint128 newPayouts = 1 ether; // example value

        validatorTicketPricer.setDailyMevPayouts(newPayouts);
        assertEq(validatorTicketPricer.getDailyMevPayouts(), newPayouts);
    }

    function testSetDailyConsensusRewards() public {
        uint128 newRewards = 1 ether; // example value
        validatorTicketPricer.setDailyConsensusRewards(newRewards);
        assertEq(validatorTicketPricer.getDailyConsensusRewards(), newRewards);
    }

    function testSetDailyRewardsAndPostMintPrice() public {
        uint128 mevPayouts = 1 ether; // example value
        uint128 consensusRewards = 1 ether; // example value
        validatorTicketPricer.setDailyRewardsAndPostMintPrice(mevPayouts, consensusRewards);
        uint16 _BPS_DECIMALS = 1e4;

        uint256 expectedPrice = (
            (_BPS_DECIMALS - validatorTicketPricer.getDiscountRateBps()) * (mevPayouts + consensusRewards)
        ) / _BPS_DECIMALS;
        assertEq(pufferOracle.getValidatorTicketPrice(), expectedPrice);
    }
}
