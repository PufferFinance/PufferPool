// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { AbstractVault } from "puffer/AbstractVault.sol";

/**
 * @title NoRestakingStrategy
 * @author Puffer Finance
 * @notice NoRestakingStrategy
 * @custom:security-contact security@puffer.fi
 */
contract NoRestakingStrategy is IPufferStrategy, AccessManaged, AbstractVault {
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
            abi.encodeWithSignature(
                "deposit(bytes,bytes,bytes,bytes32)", pubKey, getWithdrawalCredentials(), signature, depositDataRoot
            )
        );
        // @todo more logic, events
        // require(success);
    }

    /**
     * @inheritdoc IPufferStrategy
     */
    function collectNonRestakingRewards() external restricted {
        // @todo logic, send eth to pools
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
