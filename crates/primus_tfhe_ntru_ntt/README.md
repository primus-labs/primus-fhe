# primus_tfhe_ntru_ntt

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

NTRU-based TFHE with an explicit field modulus and NTT. Provides PBS, ManyLUT, factorized MVB, Boolean gates, CBS and one-hot with classic binary/ternary, sparse fixed-weight binary or direct block-binary blind rotation. External LWE and ring secrets are independent; see the [operation guide](../primus_tfhe/README.md#choosing-an-operation) and [NTRU parameter/key domains](../primus_tfhe_ntru/README.md).

## Quick start

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
```

The [basic example](examples/ntru_ntt_basic.rs) combines encrypted inputs as `z=2*x+y`, computes `score=min(z,6)`, then applies a second PBS for `price=2*score+[score>=4]`. It uses u64, input/output message modulus t=32 and external q=2^24, distinct from ring Q. Keys, LUTs, evaluator and buffers are reused; client/server stages are marked and only the final result is decrypted. Feedback needs compatible encodings, a valid padded input and enough noise margin.

## Experimental paired parameters

```rust
use primus_tfhe_ntru_ntt::{experimental, TfheContext};
use primus_ntt::U64NttTable as Table;

let config = experimental::CLASSIC_PBS_U64;
// The context uses config.messages; change its output_modulus before construction to override the default.
let context = TfheContext::<u64, Table, _>::try_from_pbs_config(config)?;
```

Start with an operation config from [experimental](src/experimental.rs). `PbsConfig` includes external q, ring Q, BR/return-KS and messages; `CbsConfig` adds CBS gadgets and uses `TfheContext::try_from_cbs_config`. These are arithmetic teaching fixtures with **unassessed security and failure probability**. Parameter and noise roles are described in the [family guide](../primus_tfhe_ntru/README.md#experimental-paired-parameters).

`PbsMessageConfig::new(t_in)` defaults to equal input/output message moduli; `.with_output_modulus(t_out)` changes the output independently. Set `config.messages` before PBS context creation, or `config.pbs.messages` for CBS. Clients and compilers derive the appropriate codecs; same-key message overrides are in [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

## Operation examples

All examples use u64 and prepare reusable state outside the request loop. Replace the example name in the quick-start command to run another local workflow; high-precision lookup runs from the separate `primus_high_prec_lut` repository root.

| Workflow | Config in `experimental` | Complete example |
| --- | --- | --- |
| Two successive PBS calls | `CLASSIC_PBS_U64` | [ntru_ntt_basic](examples/ntru_ntt_basic.rs) |
| `admin OR (member AND NOT revoked)` | `CLASSIC_PBS_U64`, messages 4→4 | [ntru_ntt_boolean](examples/ntru_ntt_boolean.rs) |
| The same scoring workflow with sparse BR | `SPARSE_PBS_U64` | [ntru_ntt_sparse](examples/ntru_ntt_sparse.rs) |
| ManyLUT grade/flag, then encrypted combination | `CLASSIC_MANY_LUT_U64` | [ntru_ntt_many_lut](examples/ntru_ntt_many_lut.rs) |
| CBS predicate → CMux → ring addition → LWE | `CLASSIC_CBS_U64` | [ntru_ntt_circuit_bootstrap](examples/ntru_ntt_circuit_bootstrap.rs) |
| 17 numeric threshold flags from one input | `CLASSIC_THRESHOLD_MVB_U64` | [ntru_ntt_mvb_thresholds](examples/ntru_ntt_mvb_thresholds.rs) |
| One-hot CBS → four-way record selection | `CLASSIC_ONE_HOT_U64` | [ntru_ntt_one_hot](examples/ntru_ntt_one_hot.rs) |
| High-precision integer lookup | Separate LUT repository's `NTT_LOW_PREC_C4_O4_DFR128_LOOKUP_U64` | [ntt_lookup](../../../primus_high_prec_lut/examples/ntt_lookup.rs) |

Ordinary PBS/ManyLUT and MVB use `context.try_generate_keys(rng)`. Bind `client.external_lwe_secret_key()` to `context.encryptor`; use `pbs_decryptor` for Rounded PBS/ManyLUT output and `mvb_decryptor` for Scaled MVB output. Public-key input uses `public_encryptor`. Clients receive no LUT or manual codec.

ManyLUT compiles through `pbs_lookup_table_compiler` / `compile_interleaved_fn` and uses `context.evaluator`. Its example maps t_in=16 to t_out=8, then combines encrypted grade/flag outputs; those cannot directly feed the differently encoded input PBS. MVB uses `compile_mvb_fn` and `mvb_evaluator` for multiple functions of one input; its Scaled flags are not Boolean gate ciphertexts.

## Parameters and representation

`TfheContext<T, Table, LM>` uses LM for external LWE q and `config.ring_modulus` for ring Q, with the same coefficient word T. The external dimension n is independent of ring length N. Use `context.allocate_lwe_ciphertext()` for external LWE storage and `allocate_accumulator_ciphertext()` for coefficient-domain NTRU storage; allocation alone does not encrypt.

PBS evaluates under ring secret f at Q, then performs coefficient-wise nearest Q→q rounding, extraction and LWE KS to external secret s at q. ManyLUT shares one Q→q conversion across its outputs; MVB converts each factor product. The return rescales an existing phase, rather than recreating q-encoding centers. For MVB, budget the difference between `(q/Q)*round(Q/t_out)` and `round(q/t_out)`, plus return noise. Independent ring-result returns use the [family return API](../primus_tfhe_ntru/README.md#ntrulwe-returns).

Ring Q uses `BarrettModulus<T>` and must admit the NTT table's primitive `2N`-th root. Custom tables implement `MonomialNttTable`; built-in tables support u32/u64. Follow the [NTT construction constraints](../primus_ntt/README.md#construction-constraints), including prime Q. Context construction checks length and modulus, while transformed keys and values must also follow the table's roots and ordering. Equal Q/N does not establish representation or actual secret identity.

CBS reverse trace uses `2^-1 mod Q`, requiring odd Q below `2^(T::BITS-1)`. This is modular normalization, not rounded integer division or an independent halving of real noise. Late key-switch errors can remain outside the projected coefficient; bound them at the output gadget scale. See the [trace contract](../primus_ntru/src/trace/ntt.rs).

NGSW-only CBS and one-hot follow `CbsConfig.projection`; the experimental NTT presets explicitly use `PairedTrace`, pairing reverse-trace stages and fusing the last two or three with scheme switching. NLev and dual outputs retain the separate path. See [`NttNtruProjectionKey`](../primus_ntru/src/scheme_switch/projection.rs) for each strategy’s storage and noise contracts. The enum default is `Separate`; choose before generating keys and evaluators:

```rust
use primus_ntt::U64NttTable;
use primus_tfhe_ntru_ntt::{experimental, NtruProjectionMethod, TfheContext};

let mut config = experimental::CLASSIC_CBS_U64;
config.projection = NtruProjectionMethod::Separate; // Override the performance preset.
let context = TfheContext::<u64, U64NttTable, _>::try_from_cbs_config(config)?;
```

Only NGSW-only output changes; it need not match the NGSW part of dual output bitwise.
See the [four-strategy comparison](../../guides/performance/README.md#ntru-projection) for timing and memory tradeoffs. Presets remain experimental; a faster strategy does not establish a smaller noise budget.

MVB requires odd ring Q; prepared factors remain in NTT form. Factor norms amplify both encrypted initialization and BR noise; return-KS noise is added afterward. MVB programs remain bound to their context. Complete encoding and factor-error conditions are in the [MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb).

Only ring secret f requires NTRU invertibility; external fixed weights may be even. Complete PBS/CBS key generation also requires f's signed coefficient magnitudes to fit below explicit return q. Shape/basis checks cannot establish actual secret identity or a noise budget; see the [family key contracts](../primus_tfhe_ntru/README.md#parameters-and-key-domains).

## Circuit bootstrapping

Create a CBS context, then use `context.try_generate_circuit_bootstrap_keys(rng)` for `(ClientKey, CircuitBootstrapServerKey)`. The bundle includes BR, return KS and CBS material; `server.server_key()` also serves ordinary PBS. CBS and one-hot themselves produce ring/gadget results without ordinary LWE return.

Compile F with `compile_cbs_fn` / `compile_cbs_slice`, then bind it with `circuit_bootstrap_evaluator_with_lookup_table`. `circuit_bootstrap_evaluator` is the identity shortcut. Input encryption uses `context.encryptor`; output is `NttNgswCiphertext` under f at gadget scales `g_j*F(m) mod Q`, with the complete output basis bound by the circuit key. CMux requires F to be bit-valued throughout the programmed domain; see the [CBS contract](../primus_tfhe/README.md#cbs-output-and-consumption).

The CBS example compiles `[m>=2]`, selects an encrypted fee plan, adds encrypted extra fees and returns one coefficient as LWE. `context.accumulator_client(client.accumulator_ntru_secret_key(), t_ring)` prepares Scaled candidate encryption/decryption at Q, without a manual codec. The example's t_ring=8 is independent of external messages and gadget scaling. Candidates must share f, Q and encoding; their coefficients are not independent SIMD slots.

Keep the context, key bundle and evaluator across requests. `_to` methods reuse scratch and caller outputs; concurrent requests need separate mutable evaluators. `KeyGenerator::try_generate_blind_rotation_key(client, rng)` generates only BR material using the context's `config.method`; independent components must use the same actual secrets and transform representation. Independent material and per-call borrowing contracts are on [KeyGenerator](src/key.rs) and [CircuitBootstrapEvaluator](src/circuit_bootstrap/evaluator.rs).

The CBS example transfers its buffers with `cbs.into_parts()` and `Evaluator::try_from_resources`, then borrows `evaluator.bootstrap_resources_mut()` for CBS/CMux. `return_ring_at_to` returns a chosen coefficient; decode it with `context.ring_return_decryptor(secret, t_ring)`, using the candidate ring message modulus. The return performs Q→q rounding and f→s key switching. Pure ring workflows can keep the owning CBS evaluator without return scratch.

CBS/one-hot operations and prepared MVB tables require their original context binding, even when another context has equal numerical parameters. For serial reuse, CBS/one-hot operations borrow `BootstrapResources` when executed. To recover ordinary PBS through `Evaluator::try_from_resources`, pass the original context and `server.server_key()`.

## Sparse blind rotation

Select `BlindRotationMethod::Sparse` in `config.method` (or `config.pbs.method` for CBS). It requires a fixed-weight binary external secret with `0<h<n`, `copy_count>=1` and `bucket_count>=max(copy_count,h)`. Changing the secret distribution alone does not select sparse; classic also supports fixed-weight secrets.

PBS, ManyLUT, MVB, CBS and one-hot support this mode. For sparse CBS/one-hot, start from `CLASSIC_ONE_HOT_U64`, whose external secret is n800/h32 fixed-weight binary. The dense `CLASSIC_CBS_U64` cannot become sparse by changing only its algorithm:

```rust,ignore
use primus_tfhe_ntru_ntt::BlindRotationMethod;

let mut config = experimental::CLASSIC_ONE_HOT_U64;
config.pbs.method = BlindRotationMethod::Sparse { copy_count: 3, bucket_count: 64 };
let context = TfheContext::<u64, Table, _>::try_from_cbs_config(config)?;
```

Generate the complete CBS bundle through `try_generate_circuit_bootstrap_keys` and use the same CBS/one-hot evaluator factories. A working PBS configuration alone does not establish CBS output precision or CMux noise margin.

## Block blind rotation

Set `config.method = BlindRotationMethod::Block` and `config.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary { block_size, occupancy }` (under `config.pbs` for CBS). The logical LWE dimension must be a nonzero multiple of the positive block width. `AtMostOne` allows empty blocks and adds an encrypted dummy; `ExactlyOne` has one `1` per block and no dummy. Neither mode uses matching or repeated controls. Generate keys and evaluate PBS, ManyLUT, MVB, CBS and one-hot through the same context factories. Each block encrypts every bit plus any mode-required dummy; the first block lifts through NLEV even when all exponents are zero, and later blocks use NGSW with the same external-product arithmetic. The shared single-input workspace allocates once and retains no occupancy information. One-hot `new_pair_workspace` / `with_pair` share grouped BR traversal for Sparse and Block; classic resources return no pair workspace and retain single-input calls. Presets remain unchanged; block noise and security need their own assessment.

## One-hot CBS

The [one-hot example](examples/ntru_ntt_one_hot.rs) uses two input bits to select one of four encrypted records. `context.one_hot_evaluator(&server)` prepares the evaluator from the same CBS bundle. Allocate once with `allocate_nonzero_ngsw_output`; only δ₁…δ₃ are generated, with C0 as the default:

```rust,ignore
one_hot.one_hot_nonzero_ngsw_to(input.as_view(), &mut selectors);
one_hot.cmux_k_to(
    one_hot.nonzero_ngsw_selectors(&selectors),
    candidates[0].as_view(),
    &candidates[1..],
    selected.as_mut_view(),
);
```

`cmux_k_to` consumes exactly branches `1..M`, paired in order with C1…C(M−1). All-zero controls select C0; a full `0..M` batch is not accepted here. Borrow individual branches with `nonzero_ngsw_selectors(...).selector(r)` using their mathematical index; `iter()` yields `(r, control)`. Full selectors and coefficient NLev output remain available through the [family one-hot API](../primus_tfhe_ntru/README.md#one-hot-cbs), which also specifies capacity and phase guards.

The fused operation computes `C0 + sum_r delta_r*(Cr-C0)` with one inverse transform. Controls must encrypt mutually exclusive bits with the bound basis, secret and transform representation; candidates must share f, Q and encoding. Budget the sum of all external-product errors, not serial CMux estimates. The [one-hot evaluator contract](src/circuit_bootstrap/one_hot_workflow.rs) specifies layouts and write/error behavior.

Candidates in the example use independent Scaled t_ring=8 and occupy ring coefficients, not SIMD slots. NLev output is coefficient-domain at Q and needs `write_ntt_form` before public-polynomial lifting; NGSW output is already in NTT representation. Single-control `cmux_to` and `external_product_to` remain available for other consumers.

## High-precision lookup

Use the separate repository’s [primus_tfhe_ntru_lut](../../../primus_high_prec_lut/README.md) for uniform-width input/output chunks with independent counts. Its `NttHighPrecLutContext` prepares integer clients, complete keys and evaluation; callers do not assemble lifting or return workspaces. The [ntt_lookup example](../../../primus_high_prec_lut/examples/ntt_lookup.rs) evaluates a piecewise fee from 16 input bits to 16 output bits.

The LUT workflow combines one-hot CBS, a fixed complete selection tree, aggregated negative rotations and independent LWE return. Recommended configs use classic BR; sparse is supported when explicitly selected. Geometry, public-table costs and numerical limits belong to the LUT crate.

## Features

Default features are empty. Normal dependencies enable `ntt`, so no backend flag is needed and standalone use does not pull in Fourier/FFT. Optional `simd` enables nightly SIMD arithmetic in dependencies; built-in NTT tables also have their own [runtime SIMD dispatch](../primus_ntt/README.md#simd-backends-and-build-target).

## Benchmarks

```sh
cargo bench -p primus_tfhe_ntru_ntt --bench pbs
```

| Target | Timed request |
| --- | --- |
| [pbs](benches/pbs.rs) | One complete PBS; dense u32/u64 and fixed-weight classic/sparse u64 |
| [many_lut](benches/many_lut.rs) | One two-output grade/flag ManyLUT, u64 |
| [mvb](benches/mvb.rs) | One 17-output threshold MVB, u64 |
| [cbs](benches/cbs.rs) | One predicate CBS, CMux and a coefficient returned as LWE, u64 |
| [one_hot](benches/one_hot.rs) | Three nonzero selectors plus four-way `cmux_k_to`, u64 |

Each iteration measures one server request with prebuilt keys, LUTs and buffers; setup and decryption checks are untimed. ManyLUT/CBS benchmarks exclude the examples' subsequent ciphertext arithmetic. Only the fixed-weight classic/sparse PBS pair changes the BR algorithm alone; dense cases use different parameters. See the [benchmark guide](../../guides/development/testing.md#tfhe-benchmarks).

## Further reading

[API sources](src/lib.rs) · [Shared encoding and errors](../primus_tfhe/README.md) · [Numerical contracts](../../guides/development/bootstrapping-contracts.md) · [Performance notes](../../guides/performance/README.md)
