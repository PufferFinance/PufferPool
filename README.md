# <h1 align="center"> Puffer </h1> 
[![Github Actions][gha-badge]][gha] [![Website][Website-badge]][Website] [![Docs][docs-badge]][docs]
  [![Discord][discord-badge]][discord] [![X][X-badge]][X] [![Foundry][foundry-badge]][foundry]

[Website-badge]: https://img.shields.io/badge/WEBSITE-8A2BE2
[Website]: https://www.puffer.fi
[X-badge]: https://img.shields.io/twitter/follow/puffer_finance
[X]: https://twitter.com/puffer_finance
[discord]: https://discord.gg/pufferfi
[docs-badge]: https://img.shields.io/badge/DOCS-8A2BE2
[docs]: https://docs.puffer.fi/
[discord-badge]: https://dcbadge.vercel.app/api/server/pufferfi?style=flat
[gha]: https://github.com/PufferFinance/PufferPool/actions
[gha-badge]: https://github.com/PufferFinance/PufferPool/actions/workflows/ci.yml/badge.svg
[foundry]: https://getfoundry.sh
[foundry-badge]: https://img.shields.io/badge/Built%20with-Foundry-FFDB1C.svg

![PUFFERS](docs/images/home.png) 

Puffer aims to provide robust and secure infrastructure for permissionless Ethereum validating, supercharged through EigenLayer restaking rewards.

Puffer supports permissionless Ethereum validators by combining cryptoeconomic mechanisms (like bonded nodes and validator tickets) and technical safeguards (such as anti-slashers and Guardians). This framework ensures that validators operate securely and contributes to the network's decentralization.

The PufferPool repo contains the smart contracts to handle all validator and restaking needs. 

### Documentation
---
- See [/docs/README.md](./docs/README.md) for technical documentation
- See the [pufETH repo](https://github.com/PufferFinance/pufETH) for information on Puffer's LRT
- See the [website docs](https://docs.puffer.fi) for information on Puffer

### Testing
---
Follow the [Foundry docs](https://book.getfoundry.sh/) for installation instructions, then install all dependencies and run tests by executing:

```
forge test
```

**Running Unit Tests**

Refine the command as follows:
```
forge test -vvv --match-path './test/unit/*'
```

**Running Fork Tests**

Fork tests require first setting the `ETH_RPC_URL` and `HOLESKY_RPC_URL` environment variables to pass (archive nodes).
```
forge test --no-match-path './test/fork-tests/*'
```
### Audit Reports
---
- Nethermind: [Audit Report](./docs/audits/Nethermind_PufferProtocol_NM0202_April2024.pdf)
- SlowMist: [todo]()
- BlockSec: [todo]()
- Creed: [todo]()

## Deployments

### Mainnet

###### Core

| Name                            | Proxy | Implementation |
| ------------------------------- | ----- | -------------- |
| PufferVault                     | [0xD9A442856C234a39a81a089C06451EBAa4306a72](https://etherscan.io/address/0xD9A442856C234a39a81a089C06451EBAa4306a72) | [0x7C93...09B6](https://etherscan.io/address/0x7C93eDab7326E5Ff8d5B89B13e3681216Ab409B6) |
| PufferDepositor                 | [0x4aA799C5dfc01ee7d790e3bf1a7C2257CE1DcefF](https://etherscan.io/address/0x4aa799c5dfc01ee7d790e3bf1a7c2257ce1dceff) | [0x55F4...a304](https://etherscan.io/address/0x55F4d6Acf015c878A88C8CD08a9D74ea0d40a304) |
| Timelock                 | - | [0x3C28...26eA](https://etherscan.io/address/0x3C28B7c7Ba1A1f55c9Ce66b263B33B204f2126eA) |
| AccessManager                 | - | [0x8c16...EE11](https://etherscan.io/address/0x8c1686069474410E6243425f4a10177a94EBEE11) |
| PufferProtocol                  | [todo]() | [todo]() |
| EnclaveVerifier                 | - | [todo]() |
| GuardianModule                  | - | [todo]() |
| PufferModuleManager                   | [todo]() | [todo]() |
| PufferOracle                          | - | [todo]() |
| PufferModuleBeacon                 | [todo]() | - |
| PufferModule                    | - | [todo]() |
| RestakingOperatorBeacon                 | [todo]() | - |
| RestakingOperator               | - | [todo]() |
| ValidatorTicket                 | [todo]() | [todo]() |

###### Multisig
| Name                            | Address |
| ------------------------------- | -------------- |
| Pauser Multisig                | [0x1ba8e3aA853F73ae8093E26B7B8F2520c3620Df4](https://etherscan.io/address/0x1ba8e3aA853F73ae8093E26B7B8F2520c3620Df4) |
| Community Multisig                | [0x446d4d6b26815f9bA78B5D454E303315D586Cb2a](https://etherscan.io/address/0x446d4d6b26815f9bA78B5D454E303315D586Cb2a) |
| Operations Multisig                | [0xC0896ab1A8cae8c2C1d27d011eb955Cca955580d](https://etherscan.io/address/0xC0896ab1A8cae8c2C1d27d011eb955Cca955580d) |


### Holesky

| Name                          | Proxy | Implementation |
| ----------------------------- | ----- | -------------- |
| PufferVault (pufETH)          | [0x98408eadD0C7cC9AebbFB2AD2787c7473Db7A1fa](https://holesky.etherscan.io/address/0x98408eadD0C7cC9AebbFB2AD2787c7473Db7A1fa) | [0x3Ed1...72F5](https://holesky.etherscan.io/address/0x3Ed1653677626C38afcf88C6Eec954EE805B72F5) |
| PufferDepositor               | [0x9BEF4B8E025ecc91FE5Ee865f4880b106F106e5a](https://holesky.etherscan.io/address/0x9BEF4B8E025ecc91FE5Ee865f4880b106F106e5a) | [0x335b...18e6](https://holesky.etherscan.io/address/0x335b6c8f5aa0073849a174c73eba985b851d18e6) |
| AccessManager                 | - | [0xA6c9...38fF](https://holesky.etherscan.io/address/0xA6c916f85DAfeb6f726E03a1Ce8d08cf835138fF) |
| PufferProtocol                | [0x705E27D6A6A0c77081D32C07DbDE5A1E139D3F14](https://holesky.etherscan.io/address/0x705E27D6A6A0c77081D32C07DbDE5A1E139D3F14) | [0xEFd2...8642](https://holesky.etherscan.io/address/0xEFd2C463CD787e1e9119873dc0cbFd0AE28D8642) |
| EnclaveVerifier                 | - | [0x7920...Df24](https://holesky.etherscan.io/address/0x79200dE6299F27b7354Ca95A09a9C3978DBEDf24) |
| GuardianModule                | - | [0xD349...b326](https://holesky.etherscan.io/address/0xD349FdCD0e4451381bfE7cba3ac28773E176b326) |
| PufferModuleManager                   | [0xe4695ab93163F91665Ce5b96527408336f070a71](https://holesky.etherscan.io/address/0xe4695ab93163F91665Ce5b96527408336f070a71) | [todo]() |
| PufferOracle                          | - | [0xEf93...7b74](https://holesky.etherscan.io/address/0xEf93AA29F627465A7f58A1F25980c90116f27b74) |
| PufferModuleBeacon                 | [0x5B81A4579f466fB17af4d8CC0ED51256b94c61D4](https://holesky.etherscan.io/address/0x5B81A4579f466fB17af4d8CC0ED51256b94c61D4) | - |
| PufferModule                    | - | [todo]() |
| RestakingOperatorBeacon                 | [0xa7DC88c059F57ADcE41070cEfEFd31F74649a261](https://holesky.etherscan.io/address/0xa7DC88c059F57ADcE41070cEfEFd31F74649a261) | - |
| RestakingOperator               | - | [todo]() |
| ValidatorTicket               | [0xA143c6bFAff0B25B485454a9a8DB94dC469F8c3b](https://holesky.etherscan.io/address/0xA143c6bFAff0B25B485454a9a8DB94dC469F8c3b) | [0x5C67...4325](https://holesky.etherscan.io/address/0x5C67fb4410797960C45e573e266A7B79d5Bb4325) |


