# Invariants

The Puffer Protocol observes certain invariants, based on its design. These are conditions that should hold true no matter what state the protocol is in, or what actions are performed upon the protocol, in any given state. These invariants are as follows:

* `pufETH should always be worth at least 1 ETH`
    * Since pufETH is an appreciating asset, this should always hold
* `Once set, the Guardians should never change`
    * We only set Guardians once, and there is no way to change the Guardians. However, the Puffer Protocol is working towards trustlessness, and the need for trusted Guardians will eventually be removed
* `The PufferPool will never lose ETH outside of provisioning nodes`
    * ETH is only ever added to the PufferPool, not removed, except in the case of provisioning 32 ETH to a Puffer NoOp to allow them to operate a validator. ETH may be added to the PufferPool via staking and rewards

