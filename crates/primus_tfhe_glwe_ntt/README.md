# primus_tfhe_glwe_ntt

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate belongs to the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts may change incompatibly.

NTT backend for GLWE TFHE with PBS, ManyLUT, factorized MVB, Boolean gates and CBS.

## Quick start

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example ntt_basic
```

Choose an operation preset from [`experimental`](src/experimental.rs). Security and failure probability are unassessed for these teaching parameters.

```rust
use primus_ntt::U64NttTable as Table;
use primus_tfhe_glwe_ntt::{TfheContext, experimental};

let config = experimental::CLASSIC_PBS_U64;
let context = TfheContext::<u64, Table>::try_from_pbs_config(config)?;
```

Set `config.messages = PbsMessageConfig::new(t_in).with_output_modulus(t_out)` to choose the input and output message moduli. For CBS, use `CbsConfig` and `TfheContext::try_from_cbs_config`.

## Operation examples

All examples use u64. Substitute the example name in the quick-start command to run a workflow.

| Workflow | Example |
| --- | --- |
| Two consecutive PBS calls | [ntt_basic](examples/ntt_basic.rs) |
| Boolean access-control gates | [ntt_boolean](examples/ntt_boolean.rs) |
| ManyLUT with grade and flag outputs | [ntt_many_lut](examples/ntt_many_lut.rs) |
| CBS predicate, CMux, ring addition and LWE return | [ntt_circuit_bootstrap](examples/ntt_circuit_bootstrap.rs) |
| 17 threshold flags from one input with MVB | [mvb_thresholds](examples/mvb_thresholds.rs) |
| Block PBS with independent q/Q in both PBS orders | [ntt_two_moduli](examples/ntt_two_moduli.rs) |
| MSB Boolean CBS to select encrypted limits | [ntt_msb_cbs](examples/ntt_msb_cbs.rs) |

Reuse the context, keys and tables. Each concurrent request needs its own mutable evaluator. Use `pbs_decryptor` for PBS/ManyLUT and `mvb_decryptor` for Scaled MVB.

## Parameters and representation

The ring modulus Q is an explicit prime admitting the NTT table's primitive `2N`-th root. `U32NttTable` and `U64NttTable` require Q below `2^30` and `2^62`, respectively. Transformed material must follow the table's roots and ordering. [NTT requirements](../primus_ntt/README.md#construction-constraints)

BR→KS accepts and returns LWE under the small secret at q. KS→BR uses the flattened ring secret at Q. Boolean gates require q=Q. Both orders support Classic and Block. [Parameters and key domains](../primus_tfhe_glwe/README.md#parameters-and-external-key-domain)

For raw Block BR, see the [single-input and batch workspaces](src/block/blind_rotation.rs). The batch workspace accepts independent inputs and returns one GLWE per input.

## Features

The optional `simd` feature enables nightly SIMD kernels.

## Benchmarks

```sh
cargo bench -p primus_tfhe_glwe_ntt --bench pbs
```

| Target | Timed workload |
| --- | --- |
| [pbs](benches/pbs.rs) | One complete Classic PBS for u32 or u64 |
| [many_lut](benches/many_lut.rs) | One two-output ManyLUT |
| [mvb](benches/mvb.rs) | One 17-output threshold MVB |
| [cbs](benches/cbs.rs) | One predicate CBS, CMux and a coefficient returned as LWE |
| [cbs_identity](benches/cbs_identity.rs) | Identity CBS ending at a transform-domain GGSW |
| [modulus_domains](benches/modulus_domains.rs) | Complete PBS comparing q=Q and q=1024 in both PBS orders |

Key generation, buffer allocation and correctness checks run outside the timed loop. See the [benchmark guide](../../guides/development/testing.md#tfhe-benchmarks) for workload selection and parameters.

## Further reading

[Operation guide](../primus_tfhe/README.md#choosing-an-operation) · [Numerical contracts](../../guides/development/bootstrapping-contracts.md) · [Performance guide](../../guides/performance/README.md)
