# primus_tfhe_glwe_ntt

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE-based TFHE with an explicit field modulus and NTT. Provides PBS, ManyLUT, factorized MVB, Boolean gates and CBS with classic binary/ternary or sparse fixed-weight binary blind rotation, in both PBS orders. See the [operation and encoding guide](../primus_tfhe/README.md#choosing-an-operation) and [GLWE parameter/key domains](../primus_tfhe_glwe/README.md).

## Quick start

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example ntt_basic
```

The [basic example](examples/ntt_basic.rs) combines encrypted inputs as `z=2*x+y`, computes `score=min(z,6)`, then feeds that ciphertext to a second PBS for `price=2*score+[score>=4]`. It uses `Word = u64`, message modulus t=32 and reusable keys, LUTs, evaluator and buffers. Client/server stages are marked in the source; only the final result is decrypted. Feedback requires both the padded input range and an adequate noise budget, not just equal message moduli.

## Experimental paired parameters

```rust
use primus_tfhe_glwe_ntt::{experimental, TfheContext};
use primus_ntt::U64NttTable as Table;

let config = experimental::CLASSIC_PBS_U64;
// The context uses config.messages; change its output_modulus before construction to override the default.
let context = TfheContext::<u64, Table>::try_from_pbs_config(config)?;
```

Start with an operation config from [experimental](src/experimental.rs). `PbsConfig` contains BR/KS, PBS order and input/output messages; `CbsConfig` adds CBS gadgets, input encoding and trace precision and uses `TfheContext::try_from_cbs_config`. NTT requires `fourier_trace_precision: FourierTracePrecision::Ordinary`; Split35 is rejected during parameter preparation. These are arithmetic teaching fixtures, **not certified security or failure-probability presets**. Numerical choices and noise roles are described in the [family guide](../primus_tfhe_glwe/README.md#experimental-paired-parameters).

`CLASSIC_CBS_U64` uses n866/N2048 with independent binary secrets, two BR levels and three trace/SS levels. Its return KS uses the small-LWE deviation, distinct from the ring-row deviation. See the [parameter directory](../../guides/development/tfhe-parameters.md#noise-by-key-role) for the tested consumer and assessment limits.

Padded CBS examples use the t8 teaching config; the MSB example explicitly selects `CbsInputEncoding::MsbBoolean` (t=2). The benchmark-local LightFHE G1 comparison uses a different input/consumer contract and is not a drop-in replacement; see [candidate scope](../../guides/performance/bootstrap-functional-comparison.md).

`PbsMessageConfig::new(t_in)` defaults to equal input/output message moduli; `.with_output_modulus(t_out)` changes the output independently. Set `config.messages` before PBS context creation, or `config.pbs.messages` for CBS. PBS and padded CBS clients/compilers derive their encodings from that choice. MSB Boolean CBS independently uses t=2. Same-key overrides are described in [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

## Operation examples

All examples use u64 and prepare reusable state outside the request loop. Replace the example name in the quick-start command to run another workflow.

| Workflow | Config in `experimental` | Complete example |
| --- | --- | --- |
| Two successive PBS calls | `CLASSIC_PBS_U64` | [ntt_basic](examples/ntt_basic.rs) |
| `admin OR (member AND NOT revoked)` | `CLASSIC_PBS_U64`, messages 4→4 | [ntt_boolean](examples/ntt_boolean.rs) |
| The same scoring workflow with sparse BR | `SPARSE_PBS_U64` | [ntt_sparse](examples/ntt_sparse.rs) |
| ManyLUT grade/flag, then encrypted combination | `CLASSIC_MANY_LUT_U64` | [ntt_many_lut](examples/ntt_many_lut.rs) |
| CBS predicate → CMux → ring addition → LWE | `CLASSIC_CBS_U64` | [ntt_circuit_bootstrap](examples/ntt_circuit_bootstrap.rs) |
| MSB Boolean NOT → encrypted service limits | `CLASSIC_CBS_U64`, MSB input | [ntt_msb_cbs](examples/ntt_msb_cbs.rs) |
| Independent q/Q with both PBS orders | Inline demonstration config | [ntt_two_moduli](examples/ntt_two_moduli.rs) |
| The same CBS workflow with sparse BR | `SPARSE_CBS_U64` | [ntt_sparse_circuit_bootstrap](examples/ntt_sparse_circuit_bootstrap.rs) |
| 17 numeric threshold flags from one input | `CLASSIC_THRESHOLD_MVB_U64` | [mvb_thresholds](examples/mvb_thresholds.rs) |

Ordinary PBS/ManyLUT and MVB use `context.try_generate_keys(rng)`. Bind the external secret from `client.external_lwe_secret_key()` to `context.encryptor`; decode PBS/ManyLUT with `pbs_decryptor`, and Scaled MVB output with `mvb_decryptor`. Public-key input uses `public_encryptor`. Clients need no LUT or manual codec.

ManyLUT compiles through `pbs_lookup_table_compiler` / `compile_interleaved_fn` and uses `context.evaluator`. Its example maps t_in=16 to t_out=8 and combines the returned grade/flag ciphertexts; they cannot feed the differently encoded input PBS directly. MVB uses `compile_mvb_fn` and `mvb_evaluator`, retaining full input resolution while factor norms amplify noise. Its Scaled flags are not Boolean gate ciphertexts; see the [shared MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb).

CBS input uses `cbs_encryptor` (or `cbs_public_encryptor`) and its `encrypt` / `encrypt_to` methods for either input mode. Ordinary `encryptor` retains PBS encoding. CBS uses `context.try_generate_circuit_bootstrap_keys(rng)`, `compile_cbs_fn` and `circuit_bootstrap_evaluator_with_lookup_table`. The examples compile `[m>=2]`, select an encrypted fee plan, add encrypted extra fees and return one coefficient as LWE. `accumulator_client(client.glwe_secret_key(), t_ring)` encrypts candidates with Scaled encoding; their t_ring=8 is independent of external messages. Ring coefficients are not independent SIMD slots. CMux requires a bit-valued function throughout the input domain, paired secrets and compatible candidates; see the [CBS contract](../primus_tfhe/README.md#cbs-output-and-consumption). Ordinary PBS can reuse `server.server_key()` from the CBS bundle.

The CBS example transfers its buffers with `cbs.into_parts()` and `Evaluator::try_from_resources`, then borrows `evaluator.bootstrap_resources_mut()` for CBS/CMux. `return_ring_at_to` returns a chosen coefficient; decode it with `context.ring_return_decryptor(secret, t_ring)`, using the candidate ring message modulus. BR→KS returns at q under the small secret; KS→BR extracts at Q under the ring secret. Pure ring workflows can keep the owning CBS evaluator without return scratch.

## Parameters and representation

The small BR input uses q (`config.small_lwe.cipher_modulus`); accumulator and ring KS use Q (`config.ring_modulus`). Presets use q=Q. BR→KS accepts/returns LWE at q, while KS→BR accepts/returns LWE at Q and converts its internal small input to q. `PbsOrder::BootstrapKeyswitch` exposes the small LWE secret (dimension n); `KeyswitchBootstrap` exposes the flattened ring secret (dimension kN). `context.allocate_lwe_ciphertext()` uses the selected external dimension. The basic example uses BR→KS; the MVB example uses KS→BR. Required KS and its independent noise are described in the [family guide](../primus_tfhe_glwe/README.md#parameters-and-external-key-domain).

Independent input reducers are selected with `PbsConfig<T, LM>` / `TfheContext<T, Table, LM>`, for example `LM = PowOf2Modulus<T>` for q=1024. Client and program factories select the correct domains automatically. Prepared evaluators use `Evaluator<T, Table>` regardless of the input reducer; they remain bound to their context and paired keys. The Boolean gate wrapper currently requires q=Q.

The backend uses `BarrettModulus<T>` with an explicit prime Q admitting a primitive `2N`-th root. Built-in `U32NttTable` / `U64NttTable` require Q below `2^30` / `2^62`, respectively; primality remains a caller precondition. See the [NTT table requirements](../primus_ntt/README.md#construction-constraints).

Custom tables must implement `MonomialNttTable`. Context construction checks length and modulus; transformed keys and values must also follow the table's roots and ordering. Equal q/N does not establish representation or actual secret identity. Keep explicit-modulus coefficients canonical; key import and encryption contracts are in [primus_glwe](../primus_glwe/README.md).

Factorized MVB requires an odd coefficient modulus. Its prepared integer factors remain in NTT form; factor norms amplify BR noise.

Sparse BR must be selected explicitly with `BlindRotationMethod::Sparse` in `config.method`; a fixed-weight secret alone still permits classic BR. Sparse requires binary weight `0<h<n`, `copy_count>=1` and `bucket_count>=max(copy_count,h)`. Both orders support PBS, ManyLUT, MVB and CBS. A working PBS configuration does not by itself establish CBS output precision or CMux noise margin.

For independent u32 or u64 inputs sharing one sparse key and LUT, `sparse::SparseGlweBlindRotationBatchWorkspace::new(key)` prepares four disjoint workspaces. `blind_rotate_lookup_table_many_to` writes a paired slice of caller-owned coefficient GLWE outputs without allocation. It interleaves groups of four on one thread, then handles a pair and a final single input as needed; single inputs retain the ordinary kernel. Inputs retain their order and individual ciphertext results; the caller decides whether to add the ring outputs or return them separately. This raw operation performs no KS/extraction. Single-input applications keep `SparseGlweBlindRotationWorkspace`.

Keep the context, keys and compiled programs across requests. `_to` methods reuse evaluator scratch and caller outputs; concurrent requests need separate mutable evaluators. MVB programs stay bound to their context. `KeyGenerator::try_generate_blind_rotation_key(client, rng)` generates only BR material using the context's `config.method`; independent components must use the same actual secrets and transform representation. Advanced material composition and per-call borrowing contracts are documented on [KeyGenerator](src/key.rs), [Evaluator](src/evaluator.rs) and [CircuitBootstrapEvaluator](src/circuit_bootstrap/evaluator.rs). Context factories prepare the default workflow directly. For borrowed CBS, compile the program first, then bind it with the chosen gadget parameters and circuit key through `CircuitBootstrapEvaluator::try_new`.

BR-only consumers such as OMR can use `BlindRotationKey::try_generate` with the input secret and target GGSW parameters, without preparing a PBS return domain. See its [generation contract](src/key.rs).

## Features

Default features are empty. Normal dependencies enable `ntt`, so no backend flag is needed and standalone use does not pull in Fourier/FFT. Optional `simd` enables nightly SIMD arithmetic in dependencies. Built-in NTT tables also have their own [runtime SIMD dispatch](../primus_ntt/README.md#simd-backends-and-build-target).

## Benchmarks

```sh
cargo bench -p primus_tfhe_glwe_ntt --bench pbs
```

| Target | Timed request |
| --- | --- |
| [pbs](benches/pbs.rs) | One complete PBS; dense u32/u64 and fixed-weight classic/sparse u64; opt-in Low/High comparison: [testing guide](../../guides/development/testing.md#tfhe-benchmarks) |
| [modulus_domains](benches/modulus_domains.rs) | Paired q=Q/q1024 complete PBS, either order; select `PRIMUS_DOMAIN_CASE=same/bk`, `split/bk`, `same/kb` or `split/kb` |
| [many_lut](benches/many_lut.rs) | One two-output grade/flag ManyLUT, u64 |
| [mvb](benches/mvb.rs) | One 17-output threshold MVB, u64 |
| [cbs](benches/cbs.rs) | One predicate CBS, CMux and a coefficient returned as LWE, u64 |
| [cbs_identity](benches/cbs_identity.rs) | Identity CBS → NTT GGSW or CBS＋CMux, bit 0/1; derived G1 Q54, padded/MSB input |

Each iteration measures one server request with prebuilt keys, LUTs and buffers; setup and workflow decryption checks are untimed. The ManyLUT/CBS targets do not include the examples' subsequent ciphertext arithmetic. Only the fixed-weight classic/sparse PBS pair changes the BR algorithm alone; dense cases use different parameters. Timing boundaries and comparison limits are in the [benchmark guide](../../guides/development/testing.md#tfhe-benchmarks).

`cbs_identity` uses a benchmark-local derived comparison configuration, not a teaching preset or an exact reproduction of the author protocol. It checks both bits with real depth-one CMux consumption before measurement; a failure aborts the run. These finite fixtures do not establish security, failure probability or deeper-tree precision; see the [parameter mapping and validation scope](../../guides/performance/bootstrap-functional-comparison.md#glwe外部cbs功能参考).

Two-stage OMR clue detection and its `classic_two_stage` / `sparse_two_stage` benchmarks live in the separate [primus_omr](../../../primus_omr/README.md) repository. Run them from that repository’s root.

## Further reading

[API sources](src/lib.rs) · [Shared encoding and errors](../primus_tfhe/README.md) · [Numerical contracts](../../guides/development/bootstrapping-contracts.md) · [Performance notes](../../guides/performance/README.md)
