# AccessManager

- <span style="color:green">AccessManager Deployed</span>: https://etherscan.io/address/0x8c1686069474410e6243425f4a10177a94ebee11

- <span style="color:green">Owner of the AccessManager</span>: https://etherscan.io/address/0x3C28B7c7Ba1A1f55c9Ce66b263B33B204f2126eA

AccessManager is a contract from OpenZeppelin and in our system it has a dual purpose. 
- It is used to manage access in the Puffer protocol.
- It can be used to pause the system in case of an emergency.

The owner of the AccessManager is the [Timelock smart contract](../lib/pufETH/docs/Timelock.md) and only the owner can change access permissions.