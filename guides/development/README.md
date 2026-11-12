# Library guide

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> [Primus FHE](../../README.md) is experimental. Its API and numerical contracts are unstable and may change incompatibly at any time.

Use the [workspace map](../../README.md#workspace-map) to find a crate and its examples. Use the guides below when composing APIs across crates.

## Read across library boundaries

Exact layouts, checks and scratch requirements are documented in the owning API's rustdoc. The guide language is marked below.

| Task | Guide |
| --- | --- |
| Choose an arithmetic domain, borrow polynomial or ciphertext views, and reuse workspaces | [Composing libraries](composition.md) (English) |
| Choose TFHE parameters, combine operation outputs or bind CBS precision and projection | [Parameter directory](tfhe-parameters.md), [bootstrapping contracts](bootstrapping-contracts.md) (English) |
| Bind BFV/BGV contexts and levels, or import raw ciphertexts for another scheme | [Scheme binding](scheme-context-binding.md) (Chinese), [RNS phase conventions](rns-phase-conventions.md) (English) |
| Persist public parameters, ciphertexts and evaluation keys | [Public storage](public-storage.md) (Chinese) |
| Choose a BFV multiplication path or prepare temporary working bases | [BFV evaluation](bfv-evaluation.md) (English), [working bases](bfv-working-basis.md) (Chinese) |
| Track BGV correction factors and prime drops | [BGV evaluation](bgv-evaluation.md) (English) |
| Build native Hybrid keys for BFV/BGV or compose collective key roles | [Native Hybrid keys](native-hybrid-keys.md) (English) |
| Select BFV/BGV parameters and review circuit budgets or security references | [Parameter and budget entry points](ordinary-parameter-budgets.md) (Chinese) |
| Run tests, examples, feature checks and benchmarks | [Testing guide](testing.md) (Chinese) |

Measurement and trade-offs are in the [performance guide](../performance/README.md). Contributor rules are in [AGENTS.md](../../AGENTS.md).
