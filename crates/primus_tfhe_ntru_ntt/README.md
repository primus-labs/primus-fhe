# primus_tfhe_ntru_ntt

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate belongs to the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts may change incompatibly.

NTT backend for NTRU TFHE with PBS, ManyLUT, factorized MVB, Boolean gates and CBS, plus one-hot.

## Quick start

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
```

Choose an operation preset from [`experimental`](src/experimental.rs). Security and failure probability are unassessed for these teaching parameters.

```rust
use primus_ntt::U64NttTable as Table;
use primus_tfhe_ntru_ntt::{TfheContext, experimental};

let config = experimental::CLASSIC_PBS_U64;
let context = TfheContext::<u64, Table, _>::try_from_pbs_config(config)?;
```

Set `config.messages = PbsMessageConfig::new(t_in).with_output_modulus(t_out)` to choose the input and output message moduli. For CBS, use `CbsConfig` and `TfheContext::try_from_cbs_config`.

## Operation examples

All examples use u64. Substitute the example name in the quick-start command to run a workflow.

| Workflow | Example |
| --- | --- |
| Two consecutive PBS calls | [ntru_ntt_basic](examples/ntru_ntt_basic.rs) |
| Boolean access-control gates | [ntru_ntt_boolean](examples/ntru_ntt_boolean.rs) |
| Block ManyLUT with grade and flag outputs | [ntru_ntt_many_lut](examples/ntru_ntt_many_lut.rs) |
| CBS predicate, CMux, ring addition and LWE return | [ntru_ntt_circuit_bootstrap](examples/ntru_ntt_circuit_bootstrap.rs) |
| 17 threshold flags from one input with MVB | [ntru_ntt_mvb_thresholds](examples/ntru_ntt_mvb_thresholds.rs) |
| One-hot CBS and four-way encrypted record selection | [ntru_ntt_one_hot](examples/ntru_ntt_one_hot.rs) |

Reuse the context, keys and tables. Each concurrent request needs its own mutable evaluator. Use `pbs_decryptor` for PBS/ManyLUT and `mvb_decryptor` for Scaled MVB.

## Parameters and representation

The ring uses an explicit prime Q with the NTT table's primitive `2N`-th root. Transformed material must follow its roots and ordering. [NTT requirements](../primus_ntt/README.md#construction-constraints)

PBS evaluates under ring secret f at Q, then rounds Q→q, extracts and switches to the external LWE key. CBS and one-hot produce gadget ciphertexts. After consuming a control, use `return_ring_at_to` to return a selected coefficient. [NTRU parameters and key domains](../primus_tfhe_ntru/README.md#parameters-and-key-domains)

`CbsConfig.projection` selects the NGSW projection before key generation. The CBS and one-hot presets use `PairedTrace`. NLEV and dual output retain separate trace and scheme switching. [Supported strategies](../../guides/development/bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support)

## Features

The optional `simd` feature enables nightly SIMD kernels.

## Benchmarks

```sh
cargo bench -p primus_tfhe_ntru_ntt --bench pbs
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
