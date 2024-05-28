// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";

import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { TestHelper } from "../helpers/TestHelper.sol";
import { Address } from "openzeppelin/utils/Address.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { IValidatorTicket } from "puffer/interface/IValidatorTicket.sol";
import { PufferOracle } from "puffer/PufferOracle.sol";
import { PufferOracleV2 } from "puffer/PufferOracleV2.sol";
import { ValidatorTicketPricer } from "puffer/ValidatorTicketPricer.sol";
import { ROLE_ID_OPERATIONS_PAYMASTER, ROLE_ID_OPERATIONS_MULTISIG, ROLE_ID_VT_PRICER } from "pufETHScript/Roles.sol";

/**
 * @dev This test is for the ValidatorTicket smart contract with `src/PufferOracle.sol`
 */
contract ValidatorTicketPricerTest is TestHelper {
    function setUp() public override {
        // Just call the parent setUp()
        super.setUp();

        vm.prank(_broadcaster);
        accessManager.grantRole(ROLE_ID_OPERATIONS_PAYMASTER, address(this), 0);
        vm.prank(_broadcaster);
        accessManager.grantRole(ROLE_ID_VT_PRICER, address(this), 0);
    }

    function testFuzz_setDailyMevPayoutsChangeToleranceBps(uint16 newValue) public {
        vm.prank(OPERATIONS_MULTISIG);

        if (newValue <= 1e4) {
            validatorTicketPricer.setDailyMevPayoutsChangeToleranceBps(newValue);
            assertEq(validatorTicketPricer.getDailyMevPayoutsChangeToleranceBps(), newValue);
        } else {
            (bool success,) = address(validatorTicketPricer).call(
                abi.encodeWithSignature("setDailyMevPayoutsChangeToleranceBps(uint16)", newValue)
            );
            assertTrue(!success);
        }
    }

    function testFuzz_setDailyConsensusRewardsChangeToleranceBps(uint16 newValue) public {
        vm.prank(OPERATIONS_MULTISIG);
        if (newValue <= 1e4) {
            validatorTicketPricer.setDailyConsensusRewardsChangeToleranceBps(newValue);
            assertEq(validatorTicketPricer.getDailyConsensusRewardsChangeToleranceBps(), newValue);
        } else {
            (bool success,) = address(validatorTicketPricer).call(
                abi.encodeWithSignature("setDailyConsensusRewardsChangeToleranceBps(uint16)", newValue)
            );
            assertTrue(!success);
        }
    }

    function testFuzz_setDiscountRate(uint16 newValue) public {
        vm.prank(DAO);
        if (newValue < 1e4) {
            validatorTicketPricer.setDiscountRate(newValue);
            assertEq(validatorTicketPricer.getDiscountRateBps(), newValue);
        } else {
            (bool success,) =
                address(validatorTicketPricer).call(abi.encodeWithSignature("setDiscountRate(uint16)", newValue));
            assertTrue(!success);
        }
    }

    function testFuzz_setDailyMevPayouts(uint128 newValue) public {
        vm.assume(newValue > 0 && newValue < 10000 ether);

        uint128 oldValue = validatorTicketPricer.getDailyMevPayouts();
        uint16 tolerance = validatorTicketPricer.getDailyMevPayoutsChangeToleranceBps();
        if (
            tolerance == 0
                || newValue <= oldValue + (oldValue * tolerance / 1e4)
                    && newValue >= oldValue - (oldValue * tolerance / 1e4)
        ) {
            validatorTicketPricer.setDailyMevPayouts(newValue);
            assertEq(validatorTicketPricer.getDailyMevPayouts(), newValue);
            validatorTicketPricer.postMintPrice();
            uint256 expectedPrice = (1e4 - validatorTicketPricer.getDiscountRateBps())
                * (newValue + validatorTicketPricer.getDailyConsensusRewards()) / 1e4;
            assertEq(pufferOracle.getValidatorTicketPrice(), expectedPrice);
        } else {
            (bool success,) =
                address(validatorTicketPricer).call(abi.encodeWithSignature("setDailyMevPayouts(uint128)", newValue));
            assertTrue(!success);
        }
    }

    function testFuzz_setDailyConsensusRewards(uint128 newValue) public {
        vm.assume(newValue > 0 && newValue < 10000 ether);
        uint128 oldValue = validatorTicketPricer.getDailyConsensusRewards();
        uint16 tolerance = validatorTicketPricer.getDailyConsensusRewardsChangeToleranceBps();
        if (
            tolerance == 0
                || newValue <= oldValue + (oldValue * tolerance / 1e4)
                    && newValue >= oldValue - (oldValue * tolerance / 1e4)
        ) {
            validatorTicketPricer.setDailyConsensusRewards(newValue);
            assertEq(validatorTicketPricer.getDailyConsensusRewards(), newValue);
            validatorTicketPricer.postMintPrice();
            uint256 expectedPrice = (1e4 - validatorTicketPricer.getDiscountRateBps())
                * (validatorTicketPricer.getDailyMevPayouts() + newValue) / 1e4;
            assertEq(pufferOracle.getValidatorTicketPrice(), expectedPrice);
        } else {
            (bool success,) = address(validatorTicketPricer).call(
                abi.encodeWithSignature("setDailyConsensusRewards(uint128)", newValue)
            );
            assertTrue(!success);
        }
    }

    function testFuzz_setDailyRewardsAndPostMintPrice(uint128 mevPayouts, uint128 consensusRewards) public {
        vm.assume(consensusRewards > 0 && consensusRewards < 10000 ether);
        vm.assume(mevPayouts > 0 && mevPayouts < 10000 ether);

        uint128 oldMevPayouts = validatorTicketPricer.getDailyMevPayouts();
        uint16 mevTolerance = validatorTicketPricer.getDailyMevPayoutsChangeToleranceBps();
        uint128 oldConsensusRewards = validatorTicketPricer.getDailyConsensusRewards();
        uint16 consensusTolerance = validatorTicketPricer.getDailyConsensusRewardsChangeToleranceBps();

        bool mevValid = mevTolerance == 0
            || mevPayouts <= oldMevPayouts + (oldMevPayouts * mevTolerance / 1e4)
                && mevPayouts >= oldMevPayouts - (oldMevPayouts * mevTolerance / 1e4);
        bool consensusValid = consensusTolerance == 0
            || consensusRewards <= oldConsensusRewards + (oldConsensusRewards * consensusTolerance / 1e4)
                && consensusRewards >= oldConsensusRewards - (oldConsensusRewards * consensusTolerance / 1e4);

        if (mevValid && consensusValid) {
            validatorTicketPricer.setDailyRewardsAndPostMintPrice(mevPayouts, consensusRewards);
            assertEq(validatorTicketPricer.getDailyMevPayouts(), mevPayouts);
            assertEq(validatorTicketPricer.getDailyConsensusRewards(), consensusRewards);
            uint256 expectedPrice =
                (1e4 - validatorTicketPricer.getDiscountRateBps()) * (mevPayouts + consensusRewards) / 1e4;
            assertEq(pufferOracle.getValidatorTicketPrice(), expectedPrice);
        } else {
            (bool success,) = address(validatorTicketPricer).call(
                abi.encodeWithSignature(
                    "setDailyRewardsAndPostMintPrice(uint128,uint128)", mevPayouts, consensusRewards
                )
            );
            assertTrue(!success);
        }
    }
}
