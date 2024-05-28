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

    function testRevertSetDailyMevPayoutsChangeToleranceBps() public {
        uint16 newTolerance = 15000; // invalid tolerance, greater than _BPS_DECIMALS

        vm.prank(OPERATIONS_MULTISIG);
        vm.expectRevert(abi.encodeWithSignature("InvalidValue()"));
        validatorTicketPricer.setDailyMevPayoutsChangeToleranceBps(newTolerance);
    }

    function testRevertSetDailyConsensusRewardsChangeToleranceBps() public {
        uint16 newTolerance = 15000; // invalid tolerance, greater than _BPS_DECIMALS

        vm.prank(OPERATIONS_MULTISIG);
        vm.expectRevert(abi.encodeWithSignature("InvalidValue()"));
        validatorTicketPricer.setDailyConsensusRewardsChangeToleranceBps(newTolerance);
    }

    function testRevertSetDiscountRate() public {
        uint16 newRate = 15000; // invalid rate, greater than or equal to _BPS_DECIMALS

        vm.prank(DAO);
        vm.expectRevert(abi.encodeWithSignature("InvalidValue()"));
        validatorTicketPricer.setDiscountRate(newRate);
    }

    function testSetDailyMevPayouts() public {
        vm.prank(_broadcaster);
        uint128 newPayouts = 1 ether; // example value

        validatorTicketPricer.setDailyMevPayouts(newPayouts);
        assertEq(validatorTicketPricer.getDailyMevPayouts(), newPayouts);

        uint16 newTolerance = 500;
        newPayouts = 0.5 ether;

        vm.prank(OPERATIONS_MULTISIG);
        validatorTicketPricer.setDailyMevPayoutsChangeToleranceBps(newTolerance);

        vm.prank(_broadcaster);

        vm.expectRevert(abi.encodeWithSignature("InvalidValue()"));
        validatorTicketPricer.setDailyMevPayouts(newPayouts);
    }

    function testSetDailyConsensusRewards() public {
        vm.prank(_broadcaster);

        uint128 newRewards = 1 ether; // example value
        validatorTicketPricer.setDailyConsensusRewards(newRewards);
        assertEq(validatorTicketPricer.getDailyConsensusRewards(), newRewards);

        uint16 newTolerance = 500;
        newRewards = 0.5 ether;

        vm.prank(OPERATIONS_MULTISIG);
        validatorTicketPricer.setDailyConsensusRewardsChangeToleranceBps(newTolerance);

        vm.prank(_broadcaster);

        vm.expectRevert(abi.encodeWithSignature("InvalidValue()"));
        validatorTicketPricer.setDailyConsensusRewards(newRewards);
    }

    function testSetDailyRewardsAndPostMintPrice() public {
        vm.prank(_broadcaster);

        uint128 mevPayouts = 1 ether; // example value
        uint128 consensusRewards = 1 ether; // example value
        validatorTicketPricer.setDailyRewardsAndPostMintPrice(mevPayouts, consensusRewards);
        uint16 _BPS_DECIMALS = 1e4;

        uint256 expectedPrice = (
            (_BPS_DECIMALS - validatorTicketPricer.getDiscountRateBps()) * (mevPayouts + consensusRewards)
        ) / _BPS_DECIMALS;
        assertEq(pufferOracle.getValidatorTicketPrice(), expectedPrice);
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

        vm.prank(_broadcaster);

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

        vm.prank(_broadcaster);
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

        vm.prank(_broadcaster);

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
