# Library guide

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> [Primus FHE](../../README.md) is experimental. Its API and numerical contracts are unstable and may change incompatibly at any time.

Choose the lowest-level crate that owns your operation. For complete TFHE applications, begin with a backend's examples; lower-level composition is optional. OMR and high-precision lookup are sibling repositories; the links below use that layout. The [workspace map](../../README.md#workspace-map) lists the core crates.

## Choose an entry point

| Need | Start here |
| --- | --- |
| Moduli, arithmetic and gadget decomposition | [primus_modulus](../../crates/primus_modulus/README.md), [primus_reduce](../../crates/primus_reduce/README.md), [primus_decompose](../../crates/primus_decompose/README.md) |
| Storage, polynomials and transforms | [primus_shape](../../crates/primus_shape/README.md), [primus_data](../../crates/primus_data/README.md), [primus_poly](../../crates/primus_poly/README.md), [primus_ntt](../../crates/primus_ntt/README.md), [primus_fft](../../crates/primus_fft/README.md) |
| Ciphertext layouts and arithmetic | [primus_lattice](../../crates/primus_lattice/README.md) |
| Messages, encoding and phase diagnostics | [primus_encoding](../../crates/primus_encoding/README.md) |
| Standalone encryption and key switching | [LWE](../../crates/primus_lwe/README.md), [GLWE](../../crates/primus_glwe/README.md), [NTRU](../../crates/primus_ntru/README.md) |
| RNS conversion, raw GLWE and gadget evaluation | [primus_rns](../../crates/primus_rns/README.md), [primus_glwe_rns](../../crates/primus_glwe_rns/README.md) |
| BFV coefficient encryption, linear/plaintext evaluation and rounded prime drop | [primus_bfv](../../crates/primus_bfv/README.md) |
| PBS, ManyLUT, MVB, CBS and Boolean gates | [Operation selection](../../crates/primus_tfhe/README.md), then [GLWE NTT](../../crates/primus_tfhe_glwe_ntt/README.md), [GLWE Fourier](../../crates/primus_tfhe_glwe_fourier/README.md), [NTRU NTT](../../crates/primus_tfhe_ntru_ntt/README.md) or [NTRU Fourier](../../crates/primus_tfhe_ntru_fourier/README.md) |
| One-hot selectors | [NTRU CBS and one-hot](../../crates/primus_tfhe_ntru/README.md#one-hot-cbs), then the backend examples |
| Functions on encrypted multi-chunk integers | [High-precision lookup](../../../primus_high_prec_lut/README.md) |
| OMR detection, digest and recovery | [primus_omr](../../../primus_omr/README.md) |

## Read across library boundaries

After the relevant crate's example, read only the topics your composition needs. Exact layouts, checks and scratch contracts remain in rustdoc.

The index is bilingual; the topic language is shown below. External tools maintain their own language entry points.

| Topic | Guide |
| --- | --- |
| Domains, representations, borrowing, phases and reusable state | [Composing libraries](composition.md) (English) |
| Native BFV/raw GLWE component signs, keys and explicit bridges | [RNS phase conventions](rns-phase-conventions.md) (English) |
| Rotation rounding, q/Q returns, CBS precision/projection support, Fourier budgets and one-hot error conditions | [Bootstrapping numerical contracts](bootstrapping-contracts.md) (English) |
| Current experimental configurations and their evidence limits | [TFHE parameter directory](tfhe-parameters.md) (English) |
| Offline NTRU CBS noise scenarios and gadget search | [Parameter analysis tool](../../../primus_high_prec_lut/tools/parameter_selection/ntru_cbs/README.md) |
| Tests, examples, features and benchmark commands | [Testing guide](testing.md) (中文) |

Performance decisions and measurements are in the [performance guide](../performance/README.md). Contributor rules are in [AGENTS.md](../../AGENTS.md).

## Common pitfalls

- Equal dimensions or buffer lengths do not establish secret, modulus, basis or transform identity.
- Borrowing a view does not convert its representation or validate coefficients. Use semantic polynomial/ciphertext iterators for batches; check complete lengths and paired counts at their boundary.
- Successful construction does not prove security or the complete operation's noise margin. Experimental configurations are functional fixtures.
- Allocate evaluators and outputs before repeated calls. Follow overwrite/accumulate contracts and give concurrent requests independent mutable state.
