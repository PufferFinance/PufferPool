# Proof of Reserves and Rewards

[Guardians](./Guardians.md) have 2 important tasks that help the protocol continue running smoothly. These are to calculate and post Proof of Reserves and Proof of Rewards. 

The purpose of Proof of Reserves is to post information about the outstanding supply of pufETH and the amount of ETH backing pufETH, so that the appropriate exchange rate between ETH and pufETH can be known and used within the protocol. This is calculated and posted once per day.

The purpose of Proof of Rewards is to determine the amount of rewards each NoOp has earned as a result of running their validators as well as opting into AVSs via the [PufferModules](./PufferModule.md). Posting Proof of Rewards allows NoOps to claim their due rewards.

Although these are currently implemented as trusted operations performed by Guardians, anyone may verify Guardians are doing their job correctly by following the processes described below. In the future these operations will be replaced with trustless Zero Knowledge Proofs.

## Proof of Reserves

<div style={{textAlign: 'center'}}>

![Proof of Reserves](./images/Proof%20of%20Reserves.png)
</div>

#### NoRestakingModule

To calculate the corresponding ETH backing pufETH, we are concerned with ETH from the following sources:

* The ETH locked on the beacon chain corresponding to active validators participating in the Puffer Protocol
* The amount of ETH in the [`PufferPool`](./PufferPool.md) smart contract
* The amount of ETH in the [`WithdrawalPool`](./WithdrawalPool.md) smart contract
* The amount of ETH that has been withdrawn from the beacon chain into the [`NoRestakingModule`](../src/NoRestakingModule.sol) contract, and has not been sent back to the pools yet

Importantly, both consensus rewards and unclaimed full withdrawal ETH may be on the `NoRestakingModule` contract at the time Guardians will calculate and post Proof of Reserves. Thus, care must be taken to separate these ETH amounts in order to do the calculation properly, since consensus rewards are claimable by Puffer NoOps, and thus do not back pufETH.

The motivation, then, is to separate these ETH amounts by moving all of the full withdrawal ETH to the pools before performing our calculations. We outline the process for calculating and posting Proof of Reserves below:

1. Guardians query the beacon chain API for the amount of ETH locked by Puffer validators
2. Guardians query the beacon chain for all withdrawals that have happened since the last time Proof of Reserves was posted, filtering only full withdrawals performed by Puffer NoOps
3. Guardians create a merkle tree with information regarding all of these full withdrawals and call the function `postFullWithdrawalRoot()`
4. This function posts the merkle tree root on chain so that NoOps may prove their full withdrawals against it and retrieve their bond. It also causes all full withdrawal ETH to move from the `NoRestakingModule` contract to both the `PufferPool` and `WithdrawalPool` contracts, according to a ratio set by governance.
5. Now that the `NoRestakingModule` contract contains no ETH amount backing pufETH, Guardians may simply query the ETH balance of the `PufferPool` and `WithdrawalPool` contracts
6. Finally, Guardians find the total oustanding supply of pufETH by calling the `totalSupply()` function on the `PufferPool` contract. They post this along with the information collected above on-chain via the `proofOfReserve()` function on the `PufferProtocol`

Now, when either the protocol or anyone wishes to know the exchange rate between ETH and pufETH, they may call the functions `calculatePufETHtoETHAmount()` and `calculateETHToPufETHAmount()` on the `PufferPool` contract, and these will use the updated values, returning the most up-to-date exchange ratio.

:::note
Note that in step 4, it is possible for one or more validators to have withdrawn close to when Proof of Reserves is calculated and posted, so the ETH from the withdrawal(s) may still be pending and not have reached the `NoRestakingModule` contract. In this case, the ETH was still accounted for during the API calls to beacon chain, but it will actually get moved off the `NoRestakingModule` contract upon the next time Proof of Reserves is calculated and posted
:::

#### RestakingModule

EigenLayer is in the process of specifying their EigenPod partial withdrawal flow. More info will be added here as it becomes available.

## Proof of Rewards

<div style={{textAlign: 'center'}}>

![Proof of Reserves](./images/Proof%20of%20Rewards.png)
</div>

#### NoRestakingModule

To calculate and post Proof of Rewards, allowing NoOps to claim their due rewards, Guardians perform the following:

1. Guardians query the beacon chain API for all withdrawals that have happened since last Proof of Rewards calculation, filtering only partial withdrawals (consensus rewards) by Puffer validators
2. Guardians map the total amount of partial withdrawals performed by each validator to the correspodning NoOp, totaling each NoOp's due rewards for this period
3. Guardians create a merkle tree with this information and post the root on-chain via a call to the function `postRewardsRoot()` on the `NoRestakingModule` contract

Now, this allows Puffer NoOps to submit a merkle proof, proving their due consensus rewards, in order to claim them, via a call to `collectNonRestakingRewards` on the `NoRestakingModule` contract. This function will verify the merkle proof and send the NoOps their due rewards.

#### RestakingModule

EigenLayer is in the process of specifying their EigenPod partial withdrawal flow. More info will be added here as it becomes available.

