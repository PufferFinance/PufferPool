// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { SafeProxy } from "safe-contracts/proxies/SafeProxy.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { Safe } from "safe-contracts/Safe.sol";

/**
 * @title SafeDeployer
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 * @notice Deploys new {Safe}
 */
abstract contract SafeDeployer {
    /**
     * @notice Deploys and initializes a {Safe} proxy smart wallet.
     * @param safeProxyFactory Address of the {Safe proxy factory}.
     * @param safeSingleton Address of the {Safe} singleton.
     * @param saltNonce Salt for the CREATE2 for {Safe}.
     * @param owners List of Safe owners.
     * @param threshold Number of required confirmations for a Safe transaction.
     * @return safe is Initialized {Safe}.
     */
    function _deploySafe(
        address safeProxyFactory,
        address safeSingleton,
        uint256 saltNonce,
        address[] calldata owners,
        bytes calldata emptyData,
        uint256 threshold
    ) internal returns (Safe) {
        address zeroAddress = address(0);

        SafeProxy proxy = SafeProxyFactory(safeProxyFactory).createProxyWithNonce({
            _singleton: safeSingleton,
            initializer: abi.encodeCall(
                Safe.setup, (owners, threshold, zeroAddress, emptyData, zeroAddress, zeroAddress, 0, payable(zeroAddress))
                ),
            saltNonce: saltNonce
        });

        return Safe(payable(address(proxy)));
    }
}
