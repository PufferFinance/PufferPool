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
- See the [website docs](https://docs.puffer.fi) for all other information on Puffer Protocol


## Deployments
For all deployment, contract addresses, ABIs, and more, see the [Deployments and ACL](https://github.com/PufferFinance/Deployments-and-ACL/tree/main/docs/deployments) repository. You can also find the deployment for each release on the [releases page](https://github.com/PufferFinance/PufferPool/releases).


## Audits
- Trail of Bits: [Audit Report](https://github.com/trailofbits/publications/blob/master/reviews/2024-03-pufferfinance-securityreview.pdf)
- Nethermind: [Audit Report](https://github.com/NethermindEth/PublicAuditReports/blob/main/NM0202-FINAL_PUFFER.pdf)
- SlowMist [Audit Report](./docs/audits/SlowMist_PufferFinance_Phase2.pdf)
- Blocksec: [Audit Report](./docs/audits/Blocksec_audit_April2024.pdf)
- Creed: [Audit Report](./docs/audits/Creed_Puffer_Finance_Audit_April2024.pdf)



# Testing
---
Follow the [Foundry docs](https://book.getfoundry.sh/) for installation instructions, then install all dependencies and run tests by executing:

```
forge test
```

## Running Unit Tests

Refine the command as follows:
```
forge test -vvv --match-path './test/unit/*'
```

## Running Fork Tests

Fork tests require first setting the `ETH_RPC_URL` and `HOLESKY_RPC_URL` environment variables to pass (archive nodes).
```
forge test --no-match-path './test/fork-tests/*'
```