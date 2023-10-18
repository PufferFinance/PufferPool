// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";

/**
 * @title NoRestakingStrategy
 * @author Puffer Finance
 * @notice NoRestakingStrategy
 * @custom:security-contact security@puffer.fi
 */
contract NoRestakingStrategy is IPufferStrategy, AccessManaged {
    /**
     * @notice Beacon chain deposit contract
     */
    address public constant BEACON_CHAIN_DEPOSIT_CONTRACT = 0x00000000219ab540356cBB839Cbe05303d7705Fa;

    /**
     * @notice Strategy Name
     */
    bytes32 public constant NAME = bytes32("NO_RESTAKING");

    constructor(address initialAuthority) AccessManaged(initialAuthority) { }

    /**
     * @notice Can Receive ETH donations
     */
    receive() external payable { }

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
                "deposit(bytes pubkey, bytes withdrawal_credentials, bytes signature, bytes32 deposit_data_root)",
                pubKey,
                getWithdrawalCredentials(),
                signature,
                depositDataRoot
            )
        );
        // @todo more logic, events
        require(success);
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
