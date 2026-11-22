# primus_tfhe_glwe_fourier

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate belongs to the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts may change incompatibly.

Fourier backend for GLWE TFHE with PBS, ManyLUT, factorized MVB, Boolean gates and CBS.

## Quick start

```sh
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic
```

Choose an operation preset from [`experimental`](src/experimental.rs). Security and failure probability are unassessed for these teaching parameters.

```rust
use primus_fft::RustFftTable as Table;
use primus_tfhe_glwe_fourier::{TfheContext, experimental};

let config = experimental::CLASSIC_PBS_U64;
let context = TfheContext::<u64, Table>::try_from_pbs_config(config)?;
```

Set `config.messages = PbsMessageConfig::new(t_in).with_output_modulus(t_out)` to choose the input and output message moduli. For CBS, use `CbsConfig` and `TfheContext::try_from_cbs_config`.

## Operation examples

All examples use u64. Substitute the example name in the quick-start command to run a workflow.

| Workflow | Example |
| --- | --- |
| Two consecutive PBS calls | [fourier_basic](examples/fourier_basic.rs) |
| Boolean access-control gates | [fourier_boolean](examples/fourier_boolean.rs) |
| ManyLUT with grade and flag outputs | [fourier_many_lut](examples/fourier_many_lut.rs) |
| CBS predicate, CMux, ring addition and LWE return | [fourier_circuit_bootstrap](examples/fourier_circuit_bootstrap.rs) |
| 17 threshold flags from one input with MVB | [fourier_mvb_thresholds](examples/fourier_mvb_thresholds.rs) |
| MSB Boolean CBS to select encrypted limits | [fourier_msb_cbs](examples/fourier_msb_cbs.rs) |

Reuse the context, keys and tables. Each concurrent request needs its own mutable evaluator. Use `pbs_decryptor` for PBS/ManyLUT and `mvb_decryptor` for Scaled MVB.

## Parameters and representation

The ring uses `NativeModulus<T>` for u32 or u64. The small-LWE modulus q may differ. Reuse the same FFT table instance for transformed keys, values and evaluators. [Fourier representation](../primus_fft/README.md) · [Coefficient key generation and migration](../primus_glwe/README.md#encryption-and-decryption)

BR→KS accepts and returns LWE under the small secret at q. KS→BR uses the flattened ring secret at Q. Boolean gates require q=Q. Both orders support Classic and Block. [Parameters and key domains](../primus_tfhe_glwe/README.md#parameters-and-external-key-domain)

With `split-trace`, `CbsConfig.fourier_trace_precision` can select `Split35` for native u64, rank one and a ring secret bounded by one. The CBS example accepts `-- --split-trace`. [Trace requirements and error budget](../../guides/development/bootstrapping-contracts.md#glwe-fourier-error-budgets)

## Features

Default features enable `rustfft` and `split-trace`. Examples use RustFFT. The general benchmarks register each enabled engine separately. Use `--no-default-features --features tfhe-fft` for TFHE-FFT alone.
Add `split-trace` when measuring Split35 with TFHE-FFT alone.

The optional `simd` feature enables nightly SIMD kernels.

## Benchmarks

```sh
cargo bench -p primus_tfhe_glwe_fourier --bench pbs
```

| Target | Timed workload |
| --- | --- |
| [pbs](benches/pbs.rs) | One complete Classic PBS for u32 or u64 |
| [many_lut](benches/many_lut.rs) | One two-output ManyLUT |
| [mvb](benches/mvb.rs) | One 17-output threshold MVB |
| [cbs](benches/cbs.rs) | One predicate CBS, CMux and a coefficient returned as LWE |
| [cbs_identity](benches/cbs_identity.rs) | Identity CBS ending at a transform-domain GGSW |
| [modulus_domains](benches/modulus_domains.rs) | Complete PBS comparing q=Q and q=1024 in both PBS orders, requires `tfhe-fft` |

Key generation, buffer allocation and correctness checks run outside the timed loop. See the [benchmark guide](../../guides/development/testing.md#tfhe-benchmarks) for workload selection and parameters.

## Further reading

[Operation guide](../primus_tfhe/README.md#choosing-an-operation) · [Numerical contracts](../../guides/development/bootstrapping-contracts.md) · [Performance guide](../../guides/performance/README.md)
