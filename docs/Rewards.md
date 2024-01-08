# Rewards

Since NoOps pay a smoothing commitment upon provisioning a validator, they are due the entirety of all their MEV rewards and consensus rewards earned during validating ETH PoS. To receive MEV rewards, they may point their fee recipient address to their own wallet address in their validator software. Here we describe the process of retrieving consensus rewards, as well as the initial pufETH bond which the NoOp locked at the time of provisioning a validator.  

## No Restaking Module

#### Claiming Partial Rewards

While performing normal validator operations, ETH will accrue upon the corresponding [PufferModule](../src/PufferModule.sol) contract whenever a validator in that module receives consensus rewards; in this case, [NoRestakingModule](../src/NoRestakingModule.sol). Periodically, Guardians will calculate all consensus rewards that are due for each NoOp, create a merkle tree with this information, and post it on-chain via `postRewardsRoot()` on the [NoRestakingModule](../src/NoRestakingModule.sol) contract. You may read more about this process [here](./Proof%20of%20Reserves%20and%20Rewards.md). Afterwards, a NoOp may call `collectRewards()` on the same contract with a valid merkle proof, proving their rewards, to retrieve their partial rewards.

#### Retrieving Bond

Upon provisioning a validator, NoOps have to lock either a 1 ETH or 2 ETH worth bond of pufETH, depending on whether they are running a TEE like SGX or not. After they have withdrawn their validator's ETH from the beacon chain, this ETH will live on the [NoRestakingModule](../src/NoRestakingModule.sol) contract, and their bond will still be locked. In order to retrieve their bond, they (or anyone) must submit a valid merkle proof, proving their full withdrawal from the beacon chain, to the function `stopValidator()` on the [PufferProtocol](../src/PufferProtocol.sol) smart contract. To facilitate this, Guardians, in a similar fashion to the above, will periodically find all full withdrawals that have happened for NoOps within the Puffer Protocol, create a merkle tree, and post this on-chain via `postFullWithdrawalsRoot()` on the [PufferProtocol](../src/PufferProtocol.sol) smart contract. Upon successful proof verification, there are the following three possible outcomes. Note that the ETH withdrawn to the [NoRestakingModule](../src/NoRestakingModule.sol) contract will return to the [PufferPool](../src/PufferPool.sol) and [WithdrawalPool](../src/WithdrawalPool.sol) contracts, according to a ratio set by governanace:

1. If the validator's balance is exactly 32 ETH, and the validator has not been slashed, the NoOp will receive all of their bond back.
2. If the validator's balance is greater than 32 ETH, and the validator has not been slashed, the NoOp will receive all of their bond back, and, in addition, they will receive the excess ETH amount above 32 ETH through the claiming partial rewards flow described above. This excess ETH amount will be counted and included in the merkle tree as partial rewards for the NoOp corresponding to this validator. 
3. If the validator's balance is less than 32 ETH, and the validator has not been slashed, the NoOp will receive their bond after the difference has been burned.
4. If the validator has been slashed, the NoOp will not receive any bond back.