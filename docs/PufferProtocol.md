# PufferProtocol

The [PufferProtocol](../src/PufferProtocol.sol) contract is the main entry point for the Puffer Protocol. This contract allows users to register their public keys with the protocol and receive 32 provisioned ETH in order to operate a validator node. Puffer NoOps may pay their smoothing commitments here in order to extend the allowed duration of operating their validators. NoOps must interact with this contract in order to stop their validator nodes as well.

Proof of reserves happen through this contract, as well as proof of full withdrawals, which NoOps may submit in order to retrieve their bonded pufETH after they are finished validating. New Puffer strategies involving various AVSs (or no AVS) may be created through this contract.

Finally, this contract maintains a queue to provision validators for NoOps, and also stores other various information about NoOps and other variables within the protocol that are maintained by governance, for example, the ratio at which ETH enters the [WithdrawalPool](./WithdrawalPool.md) upon a NoOp withdrawing from the protocol.