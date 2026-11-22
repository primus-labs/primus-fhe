# primus_tfhe_ntru_fourier

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate belongs to the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts may change incompatibly.

Fourier backend for NTRU TFHE with PBS, ManyLUT, factorized MVB, Boolean gates and CBS, plus one-hot.

## Quick start

```sh
cargo run -p primus_tfhe_ntru_fourier --release --example ntru_fourier_basic
```

Choose an operation preset from [`experimental`](src/experimental.rs). Security and failure probability are unassessed for these teaching parameters.

```rust
use primus_fft::RustFftTable as Table;
use primus_tfhe_ntru_fourier::{TfheContext, experimental};

let config = experimental::CLASSIC_PBS_U64;
let context = TfheContext::<u64, Table, _>::try_from_pbs_config(config)?;
```

Set `config.messages = PbsMessageConfig::new(t_in).with_output_modulus(t_out)` to choose the input and output message moduli. For CBS, use `CbsConfig` and `TfheContext::try_from_cbs_config`.

## Operation examples

All examples use u64. Substitute the example name in the quick-start command to run a workflow.

| Workflow | Example |
| --- | --- |
| Two consecutive PBS calls | [ntru_fourier_basic](examples/ntru_fourier_basic.rs) |
| Boolean access-control gates | [ntru_fourier_boolean](examples/ntru_fourier_boolean.rs) |
| Block ManyLUT with grade and flag outputs | [ntru_fourier_many_lut](examples/ntru_fourier_many_lut.rs) |
| CBS predicate, CMux, ring addition and LWE return | [ntru_fourier_circuit_bootstrap](examples/ntru_fourier_circuit_bootstrap.rs) |
| 17 threshold flags from one input with MVB | [ntru_fourier_mvb_thresholds](examples/ntru_fourier_mvb_thresholds.rs) |
| Split one-hot CBS and four-way encrypted record selection | [ntru_fourier_one_hot](examples/ntru_fourier_one_hot.rs) |

Reuse the context, keys and tables. Each concurrent request needs its own mutable evaluator. Use `pbs_decryptor` for PBS/ManyLUT and `mvb_decryptor` for Scaled MVB.

## Parameters and representation

The ring uses `NativeModulus<T>`. Ordinary Classic supports u32 and u64. Block and split precision require u64. Reuse the same FFT table instance for transformed keys, values and evaluators. [Fourier representation](../primus_fft/README.md) · [Coefficient key generation and migration](../primus_ntru/README.md#encryption-and-decryption)

PBS evaluates under ring secret f at Q, then rounds Q→q, extracts and switches to the external LWE key. CBS and one-hot produce gadget ciphertexts. After consuming a control, use `return_ring_at_to` to return a selected coefficient. [NTRU parameters and key domains](../primus_tfhe_ntru/README.md#parameters-and-key-domains)

`CbsConfig.fourier_precision` selects BR, trace and scheme switch precision independently. The default is `Ordinary` with `Separate` projection. The one-hot example shows split precision with `PairedTrace`. [Support matrix and numerical limits](../../guides/development/bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support)

## Features

Default features enable `rustfft`. Examples use RustFFT. The general benchmarks register each enabled engine separately. Use `--no-default-features --features tfhe-fft` for TFHE-FFT alone.

The optional `simd` feature enables nightly SIMD kernels.

## Benchmarks

```sh
cargo bench -p primus_tfhe_ntru_fourier --bench pbs
```

| Target | Timed workload |
| --- | --- |
| [pbs](benches/pbs.rs) | One complete Classic PBS for u32 or u64 |
| [many_lut](benches/many_lut.rs) | One two-output ManyLUT |
| [mvb](benches/mvb.rs) | One 17-output threshold MVB |
| [cbs](benches/cbs.rs) | One predicate CBS, CMux and a coefficient returned as LWE |
| [one_hot](benches/one_hot.rs) | Three nonzero NGSW selectors and four-way CMux |

Key generation, buffer allocation and correctness checks run outside the timed loop. See the [benchmark guide](../../guides/development/testing.md#tfhe-benchmarks) for workload selection and parameters.

## Further reading

[Operation guide](../primus_tfhe/README.md#choosing-an-operation) · [Numerical contracts](../../guides/development/bootstrapping-contracts.md) · [Performance guide](../../guides/performance/README.md)
