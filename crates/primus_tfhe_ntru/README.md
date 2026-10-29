# primus_tfhe_ntru

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Parameters and external LWE clients for NTRU-TFHE. Choose [NTT](../primus_tfhe_ntru_ntt/README.md) or [Fourier](../primus_tfhe_ntru_fourier/README.md) for contexts, evaluation keys, evaluators and complete examples. Operation and encoding choices are in the [shared guide](../primus_tfhe/README.md).

## Experimental paired parameters

Start with the concrete backend's `experimental::*_U64` operation config. These teaching fixtures have no assessed security or failure probability; see [parameter conditions](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries).

| Config | Purpose |
| --- | --- |
| `PbsConfig` | PBS, ManyLUT and MVB: external LWE, accumulator/BSK, BR algorithm, required return KS and message domains |
| `CbsConfig { pbs, gadget, projection }` | The same PBS domain plus CBS output, trace and scheme-switch decompositions; also serves one-hot |

Use backend `TfheContext::try_from_pbs_config` / `try_from_cbs_config`. Explicit preparation uses `PbsParameters::try_from_config` or `CbsParameters::try_from_config(cbs_config)`; `CbsParameters::try_with_config(pbs, gadget, projection)` reuses existing PBS parameters. `try_with_circuit_bootstrap(gadget)` adds CBS with `Separate` projection to an existing context.

PBS and CBS both require `key_switching`; CBS outputs ring/gadget ciphertexts, while the complete bundle retains KS for subsequent LWE returns. `PbsMessageConfig::new(t_in)` defaults to equal input/output message moduli; `.with_output_modulus(t_out)` changes only the output. Messages do not change the key domain.

## Parameters and key domains

`PbsParameters<T, M, LM=M>` separates ring modulus Q from external LWE modulus q while retaining coefficient type T. `external_lwe` selects dimension n, q and the external secret; `ring_modulus`, `bsk_poly_length` and `bsk_secret_distr` select the ring. n and N are independent; `2N` must fit T. Dimensions and ring length use `LweDimension` and `PolyLength`.

| Noise setting | Uses |
| --- | --- |
| `external_lwe` noise | Fresh input encryption at q |
| `bsk_gadget` noise | BR key rows, ring-candidate encryption and CBS trace/scheme-switch rows at Q |
| `key_switching` noise | Return-key rows at q |

BR and KS use separate `GadgetEncryptionConfig { decomposition, noise_standard_deviation }` values, with coefficient-unit noise at their respective moduli. CBS `output`, `trace` and `scheme_switch` each select a `DecompositionConfig`. Decomposition bases and random draws remain independent; `level_count: None` selects maximum supported levels, not necessarily zero truncation error (see [decomposition precision](../primus_decompose/README.md)).

`ClientKey` contains independently sampled external secret s and ring secret f. Only f requires NTRU invertibility and, for Fourier, inverse stability. External secrets may be binary/ternary and need neither padding nor odd weight. `client.external_lwe_secret_key()` returns s at q; family client factories check its recorded modulus. Complete PBS/CBS generation also requires f's signed coefficient magnitudes to fit below explicit return q. See [parameter](src/parameters.rs) and [NTRU secret-generation](../primus_ntru/README.md#parameters-and-keys) contracts.

Ordinary PBS follows f,Q blind rotation → coefficient-wise nearest Q→q rounding → phase extraction → LWE KS at q to s. ManyLUT shares BR and returns each output separately; `context.allocate_lwe_ciphertext()` uses n. The LUT itself is public, but NTRU lifting and BR controls contribute encryption noise. Parameter construction does not establish security or a complete noise budget.

## Sparse coefficient keys

Classic binary/ternary and sparse fixed-weight binary support PBS, ManyLUT, Boolean, MVB, CBS and one-hot. Select sparse explicitly through `config.method`; the `SparseTernary` secret distribution alone does not select bucket aggregation. External fixed weights may be even; [shared sparse restrictions](../primus_tfhe/README.md#selecting-blind-rotation) still apply.

Both backends share `NtruBlindRotationControls<T>` coefficient storage. `SparseNtruBootstrappingKey<T>` adds the public bucket map and declared weight; `controls()` borrows the common storage. Its first group contains NLev controls for lifting; later groups contain NGSW controls for encrypted rotation. NTT residues and native coefficients remain distinct representations. Prefer context/key-generator factories; see the [coefficient storage contract](src/controls.rs), [sparse grouping contract](src/sparse.rs) and [first-lift derivation](../../guides/development/bootstrapping-contracts.md#ntru-first-lifting).

Both NTRU backends also support `BlindRotationMethod::Block` with `SecretKeyDistr::BlockBinary { block_size }`. Each contiguous block has at most one `1`, including the empty state. `BlockNtruBootstrappingKey<T>` reuses the coefficient controls without a bucket map; every block stores its bit controls and an independently encrypted dummy. The first block is NLEV and must lift even an unrotated public LUT; later blocks are NGSW. PBS, ManyLUT, MVB, CBS and single-input one-hot keep their existing factories. NTRU Fourier requires u64, using exact native coefficient generation for ordinary or split BR; trace and SS precision remain independent. Both backends support scoped one-hot pairs for grouped BR; application integration and noise/security assessment are separate work. See the [block material contract](src/block.rs).

## Clients and LUTs

Ordinary PBS uses `context.try_generate_keys(rng)` for paired client/server keys. The external secret supplies `context.encryptor`, `pbs_decryptor` and `mvb_decryptor`; public input uses `public_encryptor`. They derive encodings from `config.messages` without a LUT or manual codec. `pbs_lookup_table_compiler()` and `compile_mvb_fn` use the same defaults. Family `PbsParameters` provide client factories without a transform table.

Input uses Rounded encoding at q. PBS/ManyLUT compiles Rounded output at Q and decodes at q; MVB uses Scaled at both output moduli. Return rescales an existing phase rather than freshly encoding at q, so budget scale differences, Q→q rounding and KS errors. Even equal message moduli do not guarantee feedback compatibility. Same-key message overrides are in [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding); bounded bivariate lookup currently requires q=Q.

Use `encrypt_padded` for front-half programs and `encrypt` for odd full-domain programs. Reuse output through `as_mut_view()` and read through `as_view()`; `decrypt_phase` remains available for diagnostics. `parameters.try_generate_public_key(external_secret, rng)` creates an external LWE public key, not an NTRU ring public key; account for its [additional noise](../primus_lwe/README.md#public-key-encryption).

## Boolean clients and gates

Use `PbsMessageConfig::new(4)` with the context's Boolean client/evaluator factories. Both message domains must be four for chained gates, using ordinary PBS material. See the [shared Boolean contract](../primus_tfhe/README.md#boolean-gates).

## CBS and examples

Create a CBS context and call `context.try_generate_circuit_bootstrap_keys(rng)` for `(ClientKey, CircuitBootstrapServerKey)`. This includes BR, return KS and CBS material; `server.server_key()` also supports ordinary PBS. After adding CBS through `try_with_circuit_bootstrap`, use this CBS generator, not `try_generate_keys`.

Compile identity or a custom function with `compile_cbs_identity`, `compile_cbs_fn` or `compile_cbs_slice`. Bind a program through `circuit_bootstrap_evaluator_with_lookup_table`; `circuit_bootstrap_evaluator` is the identity shortcut. Input uses `context.encryptor`; output is NGSW under f at gadget scales, without ordinary LWE return. CMux requires F to be bit-valued throughout the input domain.

`accumulator_client(client.accumulator_ntru_secret_key(), t_ring)` prepares Scaled candidates at Q. t_ring is independent of external input t; candidates must share f, Q and encoding. CBS binds the complete output basis, and BR decomposition must resolve the LUT and smallest output gadget scale. Layout checks do not prove actual secret identity or sufficient noise margin. See [CBS consumption and examples](../primus_tfhe/README.md#cbs-output-and-consumption).

NTT reverse trace uses modular inverses; Fourier uses native integer halving with additional FFT error. Scheme switching multiplies input error by f and decomposition error by f². Publishing `NGSW_f[f]` needs a justified key-dependent-message/circular-security assumption; see the [NTRU contract](../primus_ntru/README.md#same-secret-scheme-switching).

`CbsConfig.projection` selects the NGSW-only algorithm: `Separate` (the enum default), `FusedLastStage`, `FusedLastThreeStages`, or `PairedTrace`. NTRU NTT performance presets explicitly use `PairedTrace`; Fourier supports `Separate` and, with split trace and SS, `FusedLastStage` or `PairedTrace`; other choices are rejected before constructing its FFT table. NLEV-only and dual outputs retain separate trace/SS with their configured precision. Changing strategy requires reassessing the noise budget; see [`NtruProjectionMethod`](../primus_ntru/src/scheme_switch/mod.rs). Choose before preparing parameters/keys; see the [NTT configuration example](../primus_tfhe_ntru_ntt/README.md#parameters-and-representation).

## One-hot CBS

`context.one_hot_evaluator(&server)?` uses the same CBS bundle with classic binary/ternary or sparse fixed-weight binary BR. Require t=2M, M=2^tau with tau>=1; encrypt `0..M` with `encrypt_padded`. For L output levels, let `W=next_power_of_two(L)` and require `2MW<=N`.

| Output | Allocation / evaluation |
| --- | --- |
| All NLev selectors | `allocate_nlev_output` / `one_hot_nlev_to` |
| All NGSW selectors | `allocate_ngsw_output` / `one_hot_ngsw_to` |
| Nonzero NGSW branches only | `allocate_nonzero_ngsw_output` / `one_hot_nonzero_ngsw_to` |
| Both representations | `one_hot_to`, or `one_hot_nlev_and_nonzero_ngsw_to` for full NLev plus nonzero NGSW |

For Sparse and Block BR, split an owning one-hot evaluator with `into_parts`,
then call `new_pair_workspace(&resources)` and `with_pair`. The additional
`bootstrap::BlindRotationPairWorkspace` owns only the second input's exponents,
coefficient aggregate and accumulator; transforms, product scratch and selector
buffers are reused serially. The callback consumes input 0 then 1 before those
buffers are reused. NLEV-only, nonzero NGSW-only and dual projection are supported.
Classic returns `None`; consume every input through the single-input methods,
which also handle an odd final input. Paired inputs still share key errors.

Public lookup lifting needs `NLEV[1]` when no CMux selection layer performs the
first lift (`c=d`). Grouped BR has no independent classic initializer: request
`KeyGenerator::try_generate_circuit_bootstrap_keys_with_public_lift` or
`try_generate_public_lift_key`. Do not derive this material by summing the
first group's bit/dummy controls. The lift retains its own generation parameters
and adds its own decomposition/encryption error; Fourier split BR still uses
ordinary Fourier material for this public lift.

Full output covers δ_r(m), r=0..M-1. Compact NGSW slot r-1 represents r=1..M-1; m=0 makes all those target bits zero. `cmux_k_to` consumes these nonzero controls with C0 as default. NLev output is in coefficient form at Q and must be transformed before public lifting; NGSW is in the backend's transform representation for CMux.

Borrow branch views with `nlev_selectors`, `ngsw_selectors` or `nonzero_ngsw_selectors`. `selector(r)` takes the mathematical branch number; `iter()` yields `(r, ciphertext)`. Views allocate nothing. Full layout, basis and representation requirements are on the [selector types](src/one_hot/selectors.rs) and backend evaluators.

Let S=N/M and A=N/(2MW). Correct selection requires quantized phase `u_bar=S*m+W*e mod 2N` with `-A<=e<A`: the window is left-closed/right-open. e includes input noise, encoding rounding and per-coordinate quantization; shape checks prove neither this guard nor output decryptability. See the [one-hot derivation](../../guides/development/bootstrapping-contracts.md#one-hot-cbs).

The separate repository’s [high-precision LUT crate](../../../primus_high_prec_lut/README.md) handles multiple input chunks and table polynomials, with classic as the default BR and sparse available explicitly.

## NTRU→LWE returns

Ordinary PBS/MVB evaluators handle returns. For independent coefficient-domain results, this family re-exports `primus_ntru::LweReturnEvaluator` and `LweReturnBatchWorkspace`. Bind the server's return key and target q with `LweReturnEvaluator::new(server.key_switching_key(), q_modulus)`; prepare scalar or batch scratch as needed. See the [NTRU return workflow and numerical contract](../primus_ntru/README.md#independent-lwe-return) for single coefficients, shared-input prefixes and different-input streams.

## Features and further reading

Default features are empty; this family does not enable NTT/FFT. `simd` forwards to arithmetic dependencies. Select a concrete backend for evaluation.

[API sources](src/lib.rs) · [Shared operations and encoding](../primus_tfhe/README.md) · [Numerical contracts](../../guides/development/bootstrapping-contracts.md)
