// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { AbstractVault } from "puffer/AbstractVault.sol";
import { IBeaconDepositContract } from "puffer/interface/IBeaconDepositContract.sol";

/**
 * @title NoRestakingStrategy
 * @author Puffer Finance
 * @notice NoRestakingStrategy
 * @custom:security-contact security@puffer.fi
 */
contract NoRestakingStrategy is IPufferStrategy, AccessManaged, AbstractVault {
    /**
     * @notice Thrown if the deposit to beacon chain contract failed
     * @dev Signature "0x4f4a4e8e"
     */
    error FailedDeposit();

    /**
     * @notice Beacon chain deposit contract
     */
    address public immutable BEACON_CHAIN_DEPOSIT_CONTRACT;

    /**
     * @notice Strategy Name
     */
    bytes32 public constant NAME = bytes32("NO_RESTAKING");

    constructor(address initialAuthority, PufferProtocol puffer, address depositContract)
        payable
        AccessManaged(initialAuthority)
        AbstractVault(puffer)
    {
        BEACON_CHAIN_DEPOSIT_CONTRACT = depositContract;
    }

    /**
     * @notice Can Receive ETH donations
     */
    receive() external payable { }

    function setMerkleRoot() external restricted {
        //@todo
    }

    /**
     * @inheritdoc IPufferStrategy
     */
    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable
        restricted
    {
        (bool success,) = BEACON_CHAIN_DEPOSIT_CONTRACT.call(
            abi.encodeCall(
                IBeaconDepositContract.deposit, (pubKey, getWithdrawalCredentials(), signature, depositDataRoot)
            )
        );
        if (!success) {
            revert FailedDeposit();
        }
        // @todo more logic, events
    }

    /**
     * @inheritdoc IPufferStrategy
     */
    function collectNonRestakingRewards() external restricted {
        // @todo logic, send eth to pools
        // remove this silly line, just testing out the CI
        payable(BEACON_CHAIN_DEPOSIT_CONTRACT).transfer(address(this).balance);
    }

    function collectRestakingRewards() external {
        // no restaking rewards
    }

    /**
     * @inheritdoc IPufferStrategy
     */
    function getWithdrawalCredentials() public view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(this));
    }
}
