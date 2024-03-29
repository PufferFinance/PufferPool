# PufferModule

PufferModule is the owner of an *EigenPods* and is responsible for managing and interacting with the EigenLayer contracts.
When the PufferModule is created, in the `initialize()` function, we create an EigenPod.
Each PufferModule owns one EigenPod.

PufferModules will delegate their stake to certain restaking operator, and that restaking operator will do the restaking duties. 
The distribution of the restaking rewards is TBD.

## Consensus Rewards

The ETH from the beacon chain gets deposited to the EigenPod. PufferModule will query the withdrawal from the EigenPod to itself, and after it has been completed, the guardians post a merkle proof for the rewards earned by the node operators to the PufferModule smart contract by calling `postRewardsRoot`. The merkle proofs will be published, and the node operators may claim the consensus rewards from the module by calling `collectRewards`.