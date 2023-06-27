// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PodAccountInterface } from "puffer/interface/PodAccountInterface.sol";

abstract contract PodAccountBase is PodAccountInterface {
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
