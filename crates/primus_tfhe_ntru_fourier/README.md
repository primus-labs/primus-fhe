# primus_tfhe_ntru_fourier

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

NTRU-based TFHE with the native torus and Fourier transforms. Provides PBS, ManyLUT, factorized MVB, Boolean gates, CBS and one-hot with classic binary/ternary and direct block-binary blind rotation (Block requires u64). External LWE and ring secrets are independent; see the [operation guide](../primus_tfhe/README.md#choosing-an-operation) and [NTRU parameter/key domains](../primus_tfhe_ntru/README.md).

## Quick start

```sh
cargo run -p primus_tfhe_ntru_fourier --release --example ntru_fourier_basic
```

The [basic example](examples/ntru_fourier_basic.rs) combines encrypted inputs as `z=2*x+y`, computes `score=min(z,6)`, then applies a second PBS for `price=2*score+[score>=4]`. It uses u64, input/output message modulus t=32 and external q=2^24, distinct from ring Q. Keys, LUTs, evaluator and buffers are reused; client/server stages are marked and only the final result is decrypted. Feedback needs compatible encodings, a valid padded input and enough noise margin.

## Experimental paired parameters

```rust
use primus_tfhe_ntru_fourier::{experimental, TfheContext};
use primus_fft::RustFftTable as Table;

let config = experimental::CLASSIC_PBS_U64;
// The context uses config.messages; change its output_modulus before construction to override the default.
let context = TfheContext::<u64, Table, _>::try_from_pbs_config(config)?;
```

Start with an operation config from [experimental](src/experimental.rs). `PbsConfig` includes external q, ring Q, BR/return-KS and messages; `CbsConfig` adds CBS gadgets and uses `TfheContext::try_from_cbs_config`. These are arithmetic teaching fixtures with **unassessed security and failure probability**. Parameter and noise roles are described in the [family guide](../primus_tfhe_ntru/README.md#experimental-paired-parameters).

`PbsMessageConfig::new(t_in)` defaults to equal input/output message moduli; `.with_output_modulus(t_out)` changes the output independently. Set `config.messages` before PBS context creation, or `config.pbs.messages` for CBS. Clients and compilers derive the appropriate codecs; same-key message overrides are in [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

## Operation examples

All examples use u64 and prepare reusable state outside the request loop. Replace the example name in the quick-start command to run another local workflow.

| Workflow | Config in `experimental` | Complete example |
| --- | --- | --- |
| Two successive PBS calls | `CLASSIC_PBS_U64` | [ntru_fourier_basic](examples/ntru_fourier_basic.rs) |
| `admin OR (member AND NOT revoked)` | `CLASSIC_PBS_U64`, messages 4→4 | [ntru_fourier_boolean](examples/ntru_fourier_boolean.rs) |
| ManyLUT grade/flag, then encrypted combination | `CLASSIC_MANY_LUT_U64` | [ntru_fourier_many_lut](examples/ntru_fourier_many_lut.rs) |
| CBS predicate → CMux → ring addition → LWE | `CLASSIC_CBS_U64` | [ntru_fourier_circuit_bootstrap](examples/ntru_fourier_circuit_bootstrap.rs) |
| 17 numeric threshold flags from one input | `CLASSIC_THRESHOLD_MVB_U64` | [ntru_fourier_mvb_thresholds](examples/ntru_fourier_mvb_thresholds.rs) |
| Split one-hot CBS → four-way record selection | `CLASSIC_ONE_HOT_U64` + split40 / `PairedTrace` | [ntru_fourier_one_hot](examples/ntru_fourier_one_hot.rs) |

Ordinary PBS/ManyLUT and MVB use `context.try_generate_keys(rng)`. Bind `client.external_lwe_secret_key()` to `context.encryptor`; use `pbs_decryptor` for Rounded PBS/ManyLUT output and `mvb_decryptor` for Scaled MVB output. Public-key input uses `public_encryptor`. Clients receive no LUT or manual codec.

ManyLUT compiles through `pbs_lookup_table_compiler` / `compile_interleaved_fn` and uses `context.evaluator`. Its example maps t_in=16 to t_out=8, then combines encrypted grade/flag outputs; those cannot directly feed the differently encoded input PBS. MVB uses `compile_mvb_fn` and `mvb_evaluator` for multiple functions of one input; its Scaled flags are not Boolean gate ciphertexts.

## Parameters and representation

`TfheContext<T, Table, LM>` uses LM for external LWE q and `config.ring_modulus` for ring Q, with the same coefficient word T. The external dimension n is independent of ring length N. Use `context.allocate_lwe_ciphertext()` for external LWE storage and `allocate_accumulator_ciphertext()` for coefficient-domain NTRU storage; allocation alone does not encrypt.

PBS evaluates under ring secret f at Q, then performs coefficient-wise nearest Q→q rounding, extraction and LWE KS to external secret s at q. ManyLUT shares one Q→q conversion across its outputs; MVB converts each factor product. The return rescales an existing phase, rather than recreating q-encoding centers. For MVB, budget the difference between `(q/Q)*round(Q/t_out)` and `round(q/t_out)`, plus return noise. Independent ring-result returns use the [family return API](../primus_tfhe_ntru/README.md#ntrulwe-returns).

Ring Q supports `NativeModulus<T>` only; `PowOf2Modulus` rings are unsupported, although external LWE q may independently use `PowOf2Modulus`. Both `RustFftTable` and `TfheFftTable` support u32/u64. Transformed keys, values and evaluators must use the **same FFT table instance**; equal length does not establish representation identity.

Classic, public lift and CBS build native modular coefficient rows before Fourier conversion. Block controls are retained in coefficient form. Ordinary classic supports u32/u64, including fixed-weight binary secrets. Split precision and direct block BR require u64. Use `TfheContext::try_from_parameters` to bind already prepared PBS parameters with word-size validation.

When migrating from the former unreduced complex generation, regenerate affected ciphertexts and evaluation keys. If affected material was disclosed, replace the associated ring secrets and any external LWE secrets protected by the affected BR material. Re-evaluate the numerical budget for existing parameter sets.

CBS reverse trace halves unsigned coefficients with `floor(c/2)` before automorphism; it does not divide complex Fourier values. This rounding error enters the phase multiplied by ring secret f. Budget it together with trace maps, FFT and key-switch errors against the smallest output gadget scale; non-target coefficients can retain noise. See the [trace contract](../primus_ntru/src/trace/fourier.rs).

MVB requires an even actual Scaled output scale `round(2^BITS/t_out)`; odd scales return `LookupTableError::OddFactorizationScale`. Factors are transformed as signed integers without torus scaling; include FFT error. Factor norms amplify both encrypted initialization and BR noise; return-KS noise is added afterward. MVB programs remain bound to their context. Complete encoding and factor-error conditions are in the [MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb).

Only ring secret f requires NTRU invertibility and Fourier inverse-stability screening; external fixed weights may be even. Complete PBS/CBS key generation also requires f's signed coefficient magnitudes to fit below explicit return q. Shape/basis checks cannot establish actual secret identity or a noise budget; see the [family key contracts](../primus_tfhe_ntru/README.md#parameters-and-key-domains).

## Circuit bootstrapping

Create a CBS context, then use `context.try_generate_circuit_bootstrap_keys(rng)` for `(ClientKey, CircuitBootstrapServerKey)`. The bundle includes BR, return KS and CBS material; `server.server_key()` also serves ordinary PBS. CBS and one-hot themselves produce ring/gadget results without ordinary LWE return.

Compile F with `compile_cbs_fn` / `compile_cbs_slice`, then bind it with `circuit_bootstrap_evaluator_with_lookup_table`. `circuit_bootstrap_evaluator` is the identity shortcut. Input encryption uses `context.encryptor`; output is `FourierNgswCiphertext` under f at gadget scales `g_j*F(m) mod Q`, with the complete output basis bound by the circuit key. CMux requires F to be bit-valued throughout the programmed domain; see the [CBS contract](../primus_tfhe/README.md#cbs-output-and-consumption).

The CBS example compiles `[m>=2]`, selects an encrypted fee plan, adds encrypted extra fees and returns one coefficient as LWE. `context.accumulator_client(client.accumulator_ntru_secret_key(), t_ring)` prepares Scaled candidate encryption/decryption at Q, without a manual codec. The example's t_ring=8 is independent of external messages and gadget scaling. Candidates must share f, Q and encoding; their coefficients are not independent SIMD slots.

Keep the context, key bundle and evaluator across requests. `_to` methods reuse scratch and caller outputs; concurrent requests need separate mutable evaluators. `KeyGenerator::try_generate_blind_rotation_key(client, rng)` generates only BR material using the context's `config.method`; independent components must use the same actual secrets and transform representation. Independent material and per-call borrowing contracts are on [KeyGenerator](src/key.rs) and [CircuitBootstrapEvaluator](src/circuit_bootstrap/evaluator.rs).

The CBS example transfers its buffers with `cbs.into_parts()` and `Evaluator::try_from_resources`, then borrows `evaluator.bootstrap_resources_mut()` for CBS/CMux. `return_ring_at_to` returns a chosen coefficient; decode it with `context.ring_return_decryptor(secret, t_ring)`, using the candidate ring message modulus. The return performs Q→q rounding and f→s key switching. Pure ring workflows can keep the owning CBS evaluator without return scratch.

CBS/one-hot operations and prepared MVB tables require their original context binding, even when another context has equal numerical parameters. For serial reuse, CBS/one-hot operations borrow `BootstrapResources` when executed. To recover ordinary PBS through `Evaluator::try_from_resources`, pass the original context and `server.server_key()`.

## Block blind rotation

Set `config.method = BlindRotationMethod::Block` and `config.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary { block_size, occupancy }` (under `config.pbs` for CBS). Use u64 and a logical dimension divisible by that positive block width; `AtMostOne` allows empty blocks and adds a dummy, while `ExactlyOne` has one `1` per block with no dummy. The exact native generator writes every bit control and any required dummy directly in coefficient form: first-block NLEV lifts the public LUT, later NGSW rotates the ciphertext. Native aggregation is exact modulo 2^64. With split BR, the canonical aggregate is split and transformed once per block; negacyclic signs and carries are resolved before splitting. Ordinary and split external products each require a numerical error budget. PBS, ManyLUT, MVB, CBS and single-input one-hot use the existing factories and workspace.

Select BR precision through `CbsConfig.fourier_precision.blind_rotation`; PBS-only contexts use ordinary BR. Trace and SS precision remain independent, including split trace/SS with the supported projection strategies. Only the selected aggregate spectra are allocated; split conversion reuses product scratch. Context construction rejects u32 Block before preparing the transform table. One-hot `new_pair_workspace` and `with_pair` support ordinary and split Block BR. Block security and complete DFR are unassessed.

## One-hot CBS

The [one-hot example](examples/ntru_fourier_one_hot.rs) uses two input bits to select one of four encrypted records. `context.one_hot_evaluator(&server)` prepares the evaluator from the same CBS bundle. Allocate once with `allocate_nonzero_ngsw_output`; only δ₁…δ₃ are generated, with C0 as the default:

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

The fused operation computes `C0 + sum_r delta_r*(Cr-C0)` with one inverse transform. Controls must encrypt mutually exclusive bits with the bound basis, secret and transform representation; candidates must share f, Q and encoding. Budget the sum of all external-product errors, not serial CMux estimates. Fourier rounding occurs after the sum, so ciphertext coefficients need not match a sequence of CMux calls. The [one-hot evaluator contract](src/circuit_bootstrap/one_hot_workflow.rs) specifies layouts and write/error behavior.

Candidates in the example use independent Scaled t_ring=8 and occupy ring coefficients, not SIMD slots. NLev output is coefficient-domain at Q and needs `write_fourier_form` before public-polynomial lifting; NGSW output is already in Fourier representation. Single-control `cmux_to` and `external_product_to` remain available for other consumers.

## Features

RustFFT is enabled by default. Normal dependencies enable `fourier`; standalone use does not pull in NTT. Optional `simd` enables nightly SIMD arithmetic in dependencies without selecting an FFT engine.

| Cargo flags | Available engines |
| --- | --- |
| Default | RustFFT |
| `--no-default-features --features tfhe-fft` | TFHE-FFT only |
| `--features tfhe-fft` | Both, chosen by the concrete table type |
| `--no-default-features` | Generic API without a concrete engine |

Examples import `primus_fft::RustFftTable as Table` and declare `required-features = ["rustfft"]` in [Cargo.toml](Cargo.toml). Adding `--features tfhe-fft` alone does not switch them. For TFHE-FFT alone, change the example's import to `primus_fft::TfheFftTable as Table` and its target's `required-features` to `["tfhe-fft"]`, then use `--no-default-features --features tfhe-fft`. Benchmarks already instantiate each enabled engine separately.

## Benchmarks

```sh
cargo bench -p primus_tfhe_ntru_fourier --bench pbs
```

| Target | Timed request |
| --- | --- |
| [pbs](benches/pbs.rs) | One complete dense Classic PBS, u32/u64 |
| [many_lut](benches/many_lut.rs) | One two-output grade/flag ManyLUT, u64 |
| [mvb](benches/mvb.rs) | One 17-output threshold MVB, u64 |
| [cbs](benches/cbs.rs) | One predicate CBS, CMux and a coefficient returned as LWE, u64 |
| [one_hot](benches/one_hot.rs) | Three nonzero selectors plus four-way `cmux_k_to`, u64 |

Each iteration measures one server request with prebuilt keys, LUTs and buffers; setup and decryption checks are untimed. ManyLUT/CBS benchmarks exclude the examples' subsequent ciphertext arithmetic. See the [benchmark guide](../../guides/development/testing.md#tfhe-benchmarks).

Measure TFHE-FFT alone with:

```sh
cargo bench -p primus_tfhe_ntru_fourier --bench pbs --no-default-features --features tfhe-fft
```

Use `--features tfhe-fft` with default features to measure both engines separately.

## CBS Fourier precision and projection

`CbsConfig.fourier_precision` selects BR, trace and scheme switch independently;
all default to `Ordinary`. `projection` defaults to `Separate`. The
[one-hot example](examples/ntru_fourier_one_hot.rs) explicitly opts into split
arithmetic and paired projection through one complete CBS config:

```rust,no_run
use primus_tfhe_ntru_fourier::{
    experimental, CbsConfig, FourierCbsPrecision, FourierPrecision, NtruProjectionMethod,
};

let config = CbsConfig {
    fourier_precision: FourierCbsPrecision {
        blind_rotation: FourierPrecision::Split { low_bits: 40 },
        trace: FourierPrecision::Split { low_bits: 40 },
        scheme_switch: FourierPrecision::Split { low_bits: 40 },
    },
    projection: NtruProjectionMethod::PairedTrace,
    ..experimental::CLASSIC_ONE_HOT_U64
};
```

Pass this config to `TfheContext::try_from_cbs_config`, then use the same key and
evaluator factories. Callers do not provide limb buffers or scratch. For a
trace-only split experiment, keep `Separate` and set only
`config.fourier_precision.trace`.

Split requires native u64; split BR supports classic binary and block binary.
Ordinary Classic and Block BR may accompany split trace or SS.
`FusedLastStage` and `PairedTrace` both require split trace and SS, whose widths
may differ. These strategies fuse only NGSW output; NLEV/dual retain separate
trace/SS at the configured precision. SS outputs ordinary Fourier controls for
CMux. See the [support matrix and numerical limits](../../guides/development/bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support).

Split40 is an experimental choice, not a certified error budget. Fusion changes
rounding and key-error propagation; first-pair sharing additionally correlates
one-hot target errors. PairedTrace uses more key storage and one-hot scratch;
see [costs and measured tradeoffs](../../guides/performance/README.md#ntru-projection)
before selecting it for another workload. Defaults and presets remain unchanged.

## Further reading

[API sources](src/lib.rs) · [Shared encoding and errors](../primus_tfhe/README.md) · [Numerical contracts](../../guides/development/bootstrapping-contracts.md) · [Performance notes](../../guides/performance/README.md)
