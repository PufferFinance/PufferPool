# Invariants

The Puffer Protocol observes certain invariants, based on its design. These are conditions that should hold true no matter what state the protocol is in, or what actions are performed upon the protocol, in any given state. These invariants are as follows:

* `pufETH should always be worth at least 1 ETH`
    * The pufETH token is expected to be an appreciating asset as long as the validator penalties do not exceed their rewards. The protocol employs anti-slashers and the Guardians will eject validators whose balances fall too low. Thus we assume these guardrails will allow this invariant to hold
* `The PufferPool will never lose ETH outside of provisioning nodes`
    * ETH is only ever added to the PufferPool, not removed, except in the case of provisioning 32 ETH to a Puffer NoOp to allow them to operate a validator. ETH may be added to the PufferPool via staking and rewards

