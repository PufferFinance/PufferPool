# PufferModuleManager

PufferModuleManager has two main purposes.
1. It is a factory contract for creating new Puffer modules and Restaking Operators.
2. It is a hub for the calls to the Puffer modules and Restaking Operators.

It uses the UUPS upgrade pattern to allow for future upgrades to the contract.
Both PufferModules and RestakingOperators use a [beacon proxy](https://www.cyfrin.io/blog/upgradeable-proxy-smart-contract-pattern#what-is-the-beacon-proxy-pattern) pattern to allow for future upgrades.

All functionality in the PufferModule and RestakingOperator contracts is restricted to the PufferModuleManager contract.