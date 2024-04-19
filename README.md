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

| Name                            | Proxy | Implementation |
| ------------------------------- | ----- | -------------- |
| PufferVault                     | [0xD9A442856C234a39a81a089C06451EBAa4306a72](https://etherscan.io/address/0xD9A442856C234a39a81a089C06451EBAa4306a72) | [0x7C93eDab7326E5Ff8d5B89B13e3681216Ab409B6](https://etherscan.io/address/0x7C93eDab7326E5Ff8d5B89B13e3681216Ab409B6) |
| PufferDepositor                 | [0x4aa799c5dfc01ee7d790e3bf1a7c2257ce1dceff](https://etherscan.io/address/0x4aa799c5dfc01ee7d790e3bf1a7c2257ce1dceff) | [0x55F4d6Acf015c878A88C8CD08a9D74ea0d40a304](https://etherscan.io/address/0x55F4d6Acf015c878A88C8CD08a9D74ea0d40a304) |
| EnclaveVerifier                 | - | [0x5D94174199a630A8396E749ea31d80Edf84ecF16](https://etherscan.io/address/0x5D94174199a630A8396E749ea31d80Edf84ecF16) |
| GuardianModule                  | - | [0xa95aa41bBa980Eb7a80e7bfF4F6218244C723f57](https://etherscan.io/address/0xa95aa41bBa980Eb7a80e7bfF4F6218244C723f57) |
| ModuleManager                   | [0x58b56FE5ACA76DD630f48091f9d817BDA964c302](https://etherscan.io/address/0x58b56FE5ACA76DD630f48091f9d817BDA964c302) | [0xF00ed0c05F399AcE32618E64D40E6f78d3220aCA](https://etherscan.io/address/0xF00ed0c05F399AcE32618E64D40E6f78d3220aCA) |
| Oracle                          | - | [0x785a54316Af8Cb61b16a82a3f60c08A18425fA86](https://etherscan.io/address/0x785a54316Af8Cb61b16a82a3f60c08A18425fA86) |
| PufferModuleBeacon                 | [0x17883176A52c52A5579da73E2207045cfa036184](https://etherscan.io/address/0x17883176A52c52A5579da73E2207045cfa036184) | - |
| PufferModule                    | - | [0x58E4313C7e53D962977706Bf40d8C098cda9DeC3](https://etherscan.io/address/0x58E4313C7e53D962977706Bf40d8C098cda9DeC3) |
| PufferProtocol                  | [0x716B75d22B5e5f5cCa2C7229F6df79DEEe84604E](https://etherscan.io/address/0x716B75d22B5e5f5cCa2C7229F6df79DEEe84604E) | [0x55202aa4b5Ee7a37776Fa5E6eC6208c6dF95945E](https://etherscan.io/address/0x55202aa4b5Ee7a37776Fa5E6eC6208c6dF95945E) |
| RestakingOperatorBeacon                 | [0xf585669c9065877EB48f8F9678f80685084Ef305](https://etherscan.io/address/0xf585669c9065877EB48f8F9678f80685084Ef305) | - |
| RestakingOperator               | - | [0x2De37b0B6aEF362D2e49FFD3aEdE121e28dB3266](https://etherscan.io/address/0x2De37b0B6aEF362D2e49FFD3aEdE121e28dB3266) |
| ValidatorTicket                 | [0x12BD568E59F7D1A707e77F18864597eD80C3D8fb](https://etherscan.io/address/0x12BD568E59F7D1A707e77F18864597eD80C3D8fb) | [0x04dA36Dd7662a196275dA4BeB90207966e97cdf9](https://etherscan.io/address/0x04dA36Dd7662a196275dA4BeB90207966e97cdf9) |


### Holesky



| Name                          | Proxy | Implementation |
| ----------------------------- | ----- | -------------- |
| PufferVault (pufETH)          | [0x98408eadD0C7cC9AebbFB2AD2787c7473Db7A1fa](https://holesky.etherscan.io/address/0x98408eadD0C7cC9AebbFB2AD2787c7473Db7A1fa) | [0x3Ed1653677626C38afcf88C6Eec954EE805B72F5](https://holesky.etherscan.io/address/0x3Ed1653677626C38afcf88C6Eec954EE805B72F5) |
| PufferDepositor               | [0x9BEF4B8E025ecc91FE5Ee865f4880b106F106e5a](https://holesky.etherscan.io/address/0x9BEF4B8E025ecc91FE5Ee865f4880b106F106e5a) | [0x335b6c8f5aa0073849a174c73eba985b851d18e6](https://holesky.etherscan.io/address/0x335b6c8f5aa0073849a174c73eba985b851d18e6) |
| AccessManager                 | - | [0xA6c916f85DAfeb6f726E03a1Ce8d08cf835138fF](https://holesky.etherscan.io/address/0xA6c916f85DAfeb6f726E03a1Ce8d08cf835138fF) |
| GuardianModule                | - | [0xD349FdCD0e4451381bfE7cba3ac28773E176b326](https://holesky.etherscan.io/address/0xD349FdCD0e4451381bfE7cba3ac28773E176b326) |
| ValidatorTicket               | [0xA143c6bFAff0B25B485454a9a8DB94dC469F8c3b](https://holesky.etherscan.io/address/0xA143c6bFAff0B25B485454a9a8DB94dC469F8c3b) | [0x5C67fb4410797960C45e573e266A7B79d5Bb4325](https://holesky.etherscan.io/address/0x5C67fb4410797960C45e573e266A7B79d5Bb4325) |
| PufferProtocol                | [0x705E27D6A6A0c77081D32C07DbDE5A1E139D3F14](https://holesky.etherscan.io/address/0x705E27D6A6A0c77081D32C07DbDE5A1E139D3F14) | [0xEFd2C463CD787e1e9119873dc0cbFd0AE28D8642](https://holesky.etherscan.io/address/0xEFd2C463CD787e1e9119873dc0cbFd0AE28D8642) |


## Visit [./docs/Readme](./docs/Readme.md) for more documentation