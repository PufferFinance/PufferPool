# PufferProtocol

The PufferProtocol is the contract that manages the validators and is safe keeping the validators' bond and Validator Tickets.

## Registering a new validator

To register a new validator, the Node operator has a few options:
1. Pay the bond and Validator Tickets in ETH
2. Pay either the bond or the Validator Tickets in ETH and have the other transferred from the Node Operator
3. Have both the bond and Validator Tickets transferred from the Node Operator

No matter what option is chosen, the Node Operator will call the `registerValidator` function on the PufferProtocol contract.

```javascript
function registerValidatorKey(
    ValidatorKeyData calldata data,
    bytes32 moduleName,
    Permit calldata pufETHPermit,
    Permit calldata vtPermit
)
```

#### ValidatorKeyData struct

- bytes blsPubKey

This is BLS public key for the validator that the Node Operator has generated. (https://ethereum.org/en/developers/docs/consensus-mechanisms/pos/keys/)
- bytes signature;

Is the signature of the deposit data by the validator's BLS private key.

- bytes32 depositDataRoot;

Is the root hash of the deposit data.

- bytes[] blsEncryptedPrivKeyShares;

Is an array of encrypted private key shares. One share for each guardian.

- bytes blsPubKeySet;

Is the concatenated list of sharded public keys

- bytes raveEvidence;

If the Node Operator is using the Enclave, they must provide a valid RAVE evidence. The guardians will check if the RAVE is valid, and if it is not, the validator will be skipped.

#### moduleName

Is the name of the module that the validator is registering for. The module must be registered with the PufferProtocol contract.

#### pufETHPermit

Is the Permit data for `pufETH` token. If the Node Operator is paying the bond with ETH, they can submit an empty Permit struct.
If the Node Operator is transferring the bond, they must provider a valid Permit struct or do `pufETH.approve(pufferProtocol, amount)` before the registration.

#### vtPermit

Is the Permit data for `ValidatorTicket` token. If the Node Operator is paying for VT's with ETH, they can submit an empty Permit struct.
If the Node Operator is transferring VTs, they must provider a valid Permit struct or do `validatorTicket.approve(pufferProtocol, amount)` before the registration.

Upon successful registration, the Node Operator's validator will be added to the queue for provisioning. The guardians will check registration data and if everything is correct, the validator will be provisioned for `moduleName`.
Being part of the PufferModule means that the validator will by default delegate to the PufferModule's selected RestakingOperator.


## Provisioning a validator

One of the guardians will call the `provisionNode` function on the PufferProtocol contract to provision the validator.

The validator will be provisioned if:
- The registration data is correct
- There is enough liquidity for provisioning
- The BLS public key is not already in use/was not already used
- The RAVE evidence is valid (if submitted)
- Module is not excluded from the provisioning

If the guardians need to skip the validator, they can call the `skipProvisioning` function on the PufferProtocol and the Node Operator will be penalized.

`provisionNode` is one of the most important functions in the PufferProtocol contract. In the same transaction, it is taking 32 ETH from the PufferVault, it is incrementing the `_numberOfActivePufferValidators` on PufferOracleV2 contract and it is depositing the 32 ETH to the Beacon chain(PufferVault -> PufferModule -> EigenPod -> BeaconChain Deposit contract).
By doing everything in the same transaction, we are making sure that the exchange rate in the PufferVault remains the same.

The PufferVault calculates the exchange rate based on totalAssets that the Vault owns, and it is taking into the account the `PUFFER_ORACLE.getLockedEthAmount()`. 
Because we are taking 32 ETH from the Vault, we must increment the `PUFFER_ORACLE.getLockedEthAmount()` by 32 ETH so that we don't change the exchange rate.

## Exiting a validator

The node operator/guardians can broadcast a voluntary exit message to the Beacon chain and that will trigger the exit process.
After the validator is exited from the Beacon chain and the full withdrawal ETH lands in the PufferModule's EigenPod. 
The guardians will transfer ETH from the Eigen Pod to the corresponding PufferModule. With ETH sitting in the PufferModule, the guardians call `batchHandleWithdrawals`.

Here we have a couple of different scenarios:

Note: In all scenarios the `_numberOfActivePufferValidators` will be decremented on the PufferOracleV2 contract decreasing the locked eth amount by 32 ETH.

1. <span style="color:green">Full withdrawal amount >= 32 ETH</span>

32 ETH will be transferred to the PufferVault and the excess will remain in the PufferModule as a reward for the Node Operator.

2. <span style="color:orange">32 ETH < Full withdrawal amount >= Node Operator's bond</span>

32 ETH will be transferred to the PufferVault and we will burn the difference from the Node Operator's bond (32 ETH - withdrawalAmount).

3. <span style="color:red">Validator got slashed</span>

The withdrawal amount will be transferred to the PufferVault and the whole bond will be burned regardless of the slashing amount. If there is a major slashing incident, the loss will be distributed to all pufETH holders.

## Depositing Validator Tickets (VT)

A Node operator may have multiple validators running, and each running validator is consuming 1 VT per day. Because of the gas costs, we do not do any accounting of VT's on chain (`getValidatorTicketsBalance() returns(uint256)` returns the locked VT amount and not the real VT balance). The guardians are keeping track of VT consumption off chain. Periodically, the node operators will need to top up the VT balance and that can be done using `depositValidatorTickets(permit, nodeOperator)`. 

## Validator Tickets withdrawal

It can only happen if the node operator doesn't have any active or pending validators.

## Getting the rewards as a Node Operator

In Puffer, Node operators are earning Consensus + Execution rewards. The wallet that gets the execution rewards can be set in the validator configuration file depending on the validator client that is used. Look for the `fee recipient` in the documentation of the validator client.

[Consensus rewards need to be claimed from the PufferModules](./PufferModule.md#consensus-rewards). 