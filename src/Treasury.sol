// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ERC20 } from "openzeppelin/token/ERC20/ERC20.sol";
import { Ownable } from "openzeppelin/access/Ownable.sol";
import { InsuranceContract } from "puffer/InsuranceContract.sol";

// TODO: Higher premium for larger lockup period
contract Treasury is ERC20, Ownable {
    uint256 public grantsCommission;
    uint256 public referralsCommission;
    uint256 public insuranceCommission;
    uint256 public minLockupDuration;

    uint256 internal _grantsBalance;
    uint256 internal _referralsBalance;
    uint256 internal _insuranceBalance;

    receive() external payable {
        uint256 toGrants = (msg.value * grantsCommission) / 1e18;
        returnToGrants(toGrants);
        uint256 toReferrals = (msg.value * referralsCommission) / 1e18;
        returnToReferrals(toReferrals);
        uint256 toInsurance = msg.value - toReferrals - toGrants;
        returnToInsurance(toInsurance);
    }

    // TODO: Determine total supply
    constructor(
        string memory name_,
        string memory symbol_,
        uint256 _grantsCommission,
        uint256 _referralsCommission,
        uint256 _insuranceCommission,
        uint256 _minLockupDuration
    ) ERC20(name_, symbol_) Ownable(msg.sender){
        _mint(msg.sender, 1e27);
        grantsCommission = _grantsCommission;
        referralsCommission = _referralsCommission;
        insuranceCommission = _insuranceCommission;
        minLockupDuration = _minLockupDuration;
    }

    // TODO: Real initializer
    function initialize(uint256 _grantsCommission, uint256 _referralsCommission, uint256 _insuranceCommission)
        external
    {
        grantsCommission = _grantsCommission * 1e18;
        referralsCommission = _referralsCommission * 1e18;
        insuranceCommission = _insuranceCommission * 1e18;
    }

    function returnToGrants(uint256 amount) internal {
        _grantsBalance += amount;
    }

    function returnToReferrals(uint256 amount) internal {
        _referralsBalance += amount;
    }

    function returnToInsurance(uint256 amount) internal {
        _insuranceBalance += amount;
    }

    // TODO: Emit event
    function setGrantsCommission(uint256 _grantsCommission) external onlyOwner {
        grantsCommission = _grantsCommission;
    }

    function setReferralsCommission(uint256 _referralsCommission) external onlyOwner {
        referralsCommission = _referralsCommission;
    }

    function setInsuranceCommission(uint256 _insuranceCommission) external onlyOwner {
        insuranceCommission = _insuranceCommission;
    }

    function setMinLockupDuration(uint256 _minLockupDuration) external onlyOwner {
        minLockupDuration = _minLockupDuration;
    }

    // TODO: Implement
    function isValidOperator(address operator) public returns (bool) {
        return true;
    }

    // TODO: Implement
    function delegateInsurance(uint256 numPufi, address operatorAddress, uint256 lockupDuration) public {
        transferFrom(msg.sender, address(this), numPufi);
        require(isValidOperator(operatorAddress), "Invalid Operator");
        InsuranceContract insuranceContract = new InsuranceContract(address(this), msg.sender);
        insuranceContract.deposit(numPufi, lockupDuration);
        // TODO: Treasury contract calls EL contract to delegate ethDelegationAmount(numPufi) ETH to the operatorAddress
    }
}
