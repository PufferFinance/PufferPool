// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IPodAccount } from "puffer/interface/IPodAccount.sol";

abstract contract PodAccountBase is IPodAccount {
    // Pod parameters
    bytes32 POD_MRENCLAVE;
    uint256 remoteAttestationFreshnessThreshold;

    // Pod state
    struct PodParams {
        uint16 podSize;
        uint16 podThreshold;
        uint16 podKeyRotationInterval;
    }
}
