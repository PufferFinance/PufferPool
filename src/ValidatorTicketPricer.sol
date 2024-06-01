// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferOracleV2 } from "puffer/PufferOracleV2.sol";
import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";
import { IValidatorTicketPricer } from "./interface/IValidatorTicketPricer.sol";

/**
 * @title Validator Ticket Pricer
 * @notice This contract manages the pricing of validator tickets based on MEV payouts and consensus rewards.
 * @dev Uses PufferOracleV2 for price updates and inherits access control from AccessManaged.
 */
contract ValidatorTicketPricer is AccessManaged, IValidatorTicketPricer {
    uint256 internal constant _BPS_DECIMALS = 1e4; // 100%

    PufferOracleV2 internal immutable _ORACLE;

    // slot 0
    uint16 internal _dailyMevPayoutsChangeToleranceBps;
    uint16 internal _dailyConsensusRewardsChangeToleranceBps;
    uint16 internal _discountRateBps;

    // slot 1
    uint128 internal _dailyMevPayouts;
    uint128 internal _dailyConsensusRewards;

    /**
     * @notice Constructor sets the oracle and access manager
     * @param oracle The PufferOracleV2 contract address
     * @param accessManager The address of the access manager contract
     */
    constructor(PufferOracleV2 oracle, address accessManager) AccessManaged(accessManager) {
        _ORACLE = oracle;
    }

    /**
     * @inheritdoc IValidatorTicketPricer
     */
    function setDailyMevPayoutsChangeToleranceBps(uint16 newValue) external restricted {
        if (newValue > _BPS_DECIMALS) {
            revert InvalidValue();
        }

        emit DailyMevPayoutsChangeToleranceBPSUpdated(_dailyMevPayoutsChangeToleranceBps, newValue);

        _dailyMevPayoutsChangeToleranceBps = newValue;
    }

    /**
     * @inheritdoc IValidatorTicketPricer
     */
    function setDailyConsensusRewardsChangeToleranceBps(uint16 newValue) external restricted {
        if (newValue > _BPS_DECIMALS) {
            revert InvalidValue();
        }

        emit DailyConsensusRewardsChangeToleranceBPSUpdated(_dailyConsensusRewardsChangeToleranceBps, newValue);

        _dailyConsensusRewardsChangeToleranceBps = newValue;
    }

    /**
     * @inheritdoc IValidatorTicketPricer
     */
    function setDiscountRate(uint16 newValue) external restricted {
        if (newValue >= _BPS_DECIMALS) {
            revert InvalidValue();
        }

        emit DiscountRateUpdated(_discountRateBps, newValue);

        _discountRateBps = newValue;
    }

    /**
     * @inheritdoc IValidatorTicketPricer
     */
    function setDailyMevPayouts(uint128 newValue) external restricted {
        _setDailyMevPayouts(newValue);
    }

    /**
     * @inheritdoc IValidatorTicketPricer
     */
    function setDailyConsensusRewards(uint128 newValue) external restricted {
        _setDailyConsensusRewards(newValue);
    }

    /**
     * @inheritdoc IValidatorTicketPricer
     */
    function postMintPrice() external restricted {
        _postMintPrice();
    }

    /**
     * @inheritdoc IValidatorTicketPricer
     */
    function setDailyRewardsAndPostMintPrice(uint128 dailyMevPayouts, uint128 dailyConsensusRewards)
        external
        restricted
    {
        _setDailyMevPayouts(dailyMevPayouts);
        _setDailyConsensusRewards(dailyConsensusRewards);
        _postMintPrice();
    }

    /**
     * @inheritdoc IValidatorTicketPricer
     */
    function getDailyMevPayoutsChangeToleranceBps() external view returns (uint16) {
        return _dailyMevPayoutsChangeToleranceBps;
    }

    /**
     * @inheritdoc IValidatorTicketPricer
     */
    function getDailyConsensusRewardsChangeToleranceBps() external view returns (uint16) {
        return _dailyConsensusRewardsChangeToleranceBps;
    }

    /**
     * @inheritdoc IValidatorTicketPricer
     */
    function getDiscountRateBps() external view returns (uint16) {
        return _discountRateBps;
    }

    /**
     * @inheritdoc IValidatorTicketPricer
     */
    function getDailyMevPayouts() external view returns (uint128) {
        return _dailyMevPayouts;
    }

    /**
     * @inheritdoc IValidatorTicketPricer
     */
    function getDailyConsensusRewards() external view returns (uint128) {
        return _dailyConsensusRewards;
    }

    /**
     * @notice Checks if the new price is within the allowed range
     * @param oldValue The old price
     * @param newValue The new price to set for minting VT
     * @param toleranceBps The allowed tolerance in basis points
     * @return true if the new price is within the allowed range
     */
    function isWithinRange(uint128 oldValue, uint128 newValue, uint16 toleranceBps) internal pure returns (bool) {
        if (toleranceBps == 0) {
            return true;
        }

        uint256 allowedDifference = (oldValue * toleranceBps) / _BPS_DECIMALS;

        if (newValue > oldValue) {
            return newValue <= oldValue + allowedDifference;
        }

        return newValue >= oldValue - allowedDifference;
    }

    /**
     * @notice Posts the mint price to the oracle
     * @dev Calculates the new price based on MEV payouts and consensus rewards, applies the discount rate, and updates the oracle
     */
    function _postMintPrice() internal {
        uint256 newPrice =
            ((_BPS_DECIMALS - _discountRateBps) * (_dailyMevPayouts + _dailyConsensusRewards)) / _BPS_DECIMALS;
        if (newPrice == 0) {
            revert InvalidValue();
        }

        _ORACLE.setMintPrice(newPrice);
    }

    /**
     * @notice Sets the daily consensus rewards value
     * @param newValue The new daily consensus rewards value to set
     * @dev Checks if the new value is within the allowed range and emits an event
     */
    function _setDailyConsensusRewards(uint128 newValue) internal {
        uint128 oldValue = _dailyConsensusRewards;

        if (!isWithinRange(oldValue, newValue, _dailyConsensusRewardsChangeToleranceBps)) {
            revert InvalidValue();
        }

        emit DailyConsensusRewardsUpdated(oldValue, newValue);

        _dailyConsensusRewards = newValue;
    }

    /**
     * @notice Sets the daily MEV payouts value
     * @param newValue The new daily MEV payouts value to set
     * @dev Checks if the new value is within the allowed range and emits an event
     */
    function _setDailyMevPayouts(uint128 newValue) internal {
        uint128 oldValue = _dailyMevPayouts;

        if (!isWithinRange(oldValue, newValue, _dailyMevPayoutsChangeToleranceBps)) {
            revert InvalidValue();
        }

        emit DailyMevPayoutsUpdated(oldValue, newValue);

        _dailyMevPayouts = newValue;
    }
}
