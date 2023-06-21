// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "src/interface/PodAccountInterface.sol";
// import "@openzeppelin-contracts/finance/PaymentSplitter.sol";

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
