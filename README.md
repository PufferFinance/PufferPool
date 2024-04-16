# <h1 align="center"> Puffer Protocol </h1> 
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

![PUFFERS](image.png) 

# Tests

Please use `foundryup -v nightly-de33b6af53005037b463318d2628b5cfcaf39916` in the more recent versions the tests are broken because blockhash(0) changed.

Installing dependencies and running tests can be executed running:

`forge test`

For unit tests:
```
forge test -vvv --match-path './test/unit/*'
```

For fork tests tests:
Make sure you have a valid `ETH_RPC_URL` and `HOLESKY_RPC_URL` environment variables set (archive node rpc)
```
forge test --no-match-path './test/unit/*'
```

# Deployments

### Mainnet

```javascript
PufferVault(pufETH): 0xD9A442856C234a39a81a089C06451EBAa4306a72
PufferDepositor: 0x4aa799c5dfc01ee7d790e3bf1a7c2257ce1dceff
AccessManager: 0x8c1686069474410E6243425f4a10177a94EBEE11
EnclaveVerifier: 0x5D94174199a630A8396E749ea31d80Edf84ecF16
GuardianModule: 0xa95aa41bBa980Eb7a80e7bfF4F6218244C723f57
ModuleManager: 0x58b56FE5ACA76DD630f48091f9d817BDA964c302
PufferOracle: 0x785a54316Af8Cb61b16a82a3f60c08A18425fA86
PufferProtocol: 0x716B75d22B5e5f5cCa2C7229F6df79DEEe84604E
ValidatorTicket: 0x12BD568E59F7D1A707e77F18864597eD80C3D8fb
```

### Holesky

```javascript
PufferVault(pufETH): 0x98408eadD0C7cC9AebbFB2AD2787c7473Db7A1fa
PufferDepositor: 0x9BEF4B8E025ecc91FE5Ee865f4880b106F106e5a
AccessManager: 0xA6c916f85DAfeb6f726E03a1Ce8d08cf835138fF
GuardianModule: 0xD349FdCD0e4451381bfE7cba3ac28773E176b326
ValidatorTicket: 0xA143c6bFAff0B25B485454a9a8DB94dC469F8c3b
PufferProtocol: 0x705E27D6A6A0c77081D32C07DbDE5A1E139D3F14
```

## Visit [./docs/Readme](./docs/Readme.md) for more documentation