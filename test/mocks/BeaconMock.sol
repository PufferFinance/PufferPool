// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract BeaconMock {
    event StartedStaking();

    error BadValue();

    function deposit(
        bytes calldata pubkey,
        bytes calldata withdrawal_credentials,
        bytes calldata signature,
        bytes32 deposit_data_root
    ) external payable {
        if (msg.value != 32 ether) {
            revert BadValue();
        }
        emit StartedStaking();
    }
}
