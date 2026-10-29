# primus_tfhe_glwe

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Backend-independent GLWE-TFHE parameters and LWE clients. Choose [NTT](../primus_tfhe_glwe_ntt/README.md) or [Fourier](../primus_tfhe_glwe_fourier/README.md) for contexts, server keys, evaluators and complete examples. Client ciphertexts are LWE; GLWE is the accumulator family. Operation and encoding choices are in the [shared guide](../primus_tfhe/README.md).

## Experimental paired parameters

Start with the concrete backend's `experimental::*_U64` operation config. These are teaching fixtures, not certified security or failure-probability presets; see [parameter conditions](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries).

| Config | Purpose |
| --- | --- |
| `PbsConfig` | PBS, ManyLUT and MVB: small LWE, accumulator/BSK, BR method, required KS, PBS order and message domains |
| `CbsConfig { pbs, gadget, input_encoding, fourier_trace_precision }` | The same PBS domain plus CBS output, trace and scheme-switch decompositions |

Use backend `TfheContext::try_from_pbs_config` / `try_from_cbs_config`. Explicit preparation uses `PbsParameters::try_from_config` or `CbsParameters::try_from_config(cbs_config)`; `CbsParameters::try_with_config` accepts existing PBS parameters. `try_with_circuit_bootstrap(gadget, input_encoding, fourier_trace_precision)` adds CBS to an existing context.

Both configurations require `key_switching`. The CBS stage outputs ring/gadget ciphertexts, but its complete key bundle retains KS for input preparation or downstream LWE returns. `PbsMessageConfig::new(t_in)` defaults to equal input/output message moduli; `.with_output_modulus(t_out)` changes only the output. Messages do not change the key domain.

## Parameters and external key domain

`PbsConfig<T, M, LM = M>` separates small-LWE q (`small_lwe.cipher_modulus`, reducer LM) from accumulator Q (`ring_modulus`, reducer M). Same-domain presets specify the same value in both fields. `small_lwe` describes the small BR-control secret and fresh noise. `bsk_dimension`, `bsk_poly_length` and `bsk_secret_distr` describe the ring secret and layout shared by accumulator and BSK; `bsk_gadget` supplies BSK decomposition and row noise. Public `(0, LUT * X^(-b))` initialization samples no encryption noise.

`GadgetEncryptionConfig { decomposition, noise_standard_deviation }` configures BR and KS separately. Decomposition uses `DecompositionConfig { log_basis, level_count }`; `level_count: None` chooses the maximum supported levels but may still omit low bits (see [decomposition precision](../primus_decompose/README.md)). Use `LweDimension`, `GlweDimension` and `PolyLength` for dimensions and ring length.

| Noise setting | Uses / coefficient domain |
| --- | --- |
| `small_lwe` noise | Fresh small-LWE encryption at q |
| `bsk_gadget` noise | BSK rows, ring-candidate encryption, fresh external encryption for KS→BR, CBS trace/scheme-switch rows, all at Q |
| `key_switching` noise | Ring-KS rows at Q in either PBS order |

All standard deviations use coefficient units. KS noise is independent of BR noise. CBS `output`, `trace` and `scheme_switch` decompositions are independent; trace/scheme-switch encryption uses the accumulator noise.

| `PbsOrder` | PBS chain | External secret / dimension / modulus |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR(Q) → ring KS(Q) → compact extraction → MS Q→q | Small LWE / n / q |
| `KeyswitchBootstrap` | Inverse extraction(Q) → ring KS(Q) → compact extraction → MS Q→q → BR(Q) → full extraction | Flattened GLWE / kN / Q |

Both orders return under their external secret and modulus. Equal q/Q skips the conversion pass. Modulus switching rounds ciphertext coordinates; it cannot reinterpret q residues as Q residues. `ring_modulus()` names Q explicitly; `external_modulus()` returns the order-selected reducer when both domains use the same reducer type; `external_modulus_value()` follows the order (`None` means the native torus). Obtain it with `client.external_lwe_secret_key()`; `context.allocate_lwe_ciphertext()` uses that dimension. Small secrets must be binary or ternary with `n<=kN`, and `2N` must fit the coefficient word. Gaussian small secrets are unsupported; accumulator secrets may be Gaussian subject to backend magnitude bounds. Parameter compatibility does not prove secret identity or a noise/security budget. Full numerical contracts are on [PbsParameters](src/parameters.rs).

Raw GLWE blind-rotation calls take a separately prepared `RotationModulusSwitch<T>` for the key's input q and ring domain 2N. Use step one for ordinary PBS, and the LUT's padded output width for interleaved operations. Context evaluators bind this automatically; applications do not need to manage quantizers. See [rotation quantization](../primus_tfhe/src/rotation.rs) and the backend BR contracts.

## Sparse coefficient keys

Classic binary/ternary and sparse fixed-weight binary work with both orders, including PBS, ManyLUT, MVB and CBS. Select `config.method = BlindRotationMethod::Sparse { copy_count, bucket_count }` explicitly; the [shared selection rules](../primus_tfhe/README.md#selecting-blind-rotation) apply.

The backends share `GlweBlindRotationControls<T, M>` for coefficient controls and their numerical layout; `SparseGlweBootstrappingKey` adds the public bucket map and fixed weight. Borrow the controls with `key.controls()` when allocating a raw BR workspace. NTT uses Barrett residues and Fourier uses Native coefficients, so those representations are not interchangeable. Prefer context/key-generator factories and ordinary evaluators; storage and import contracts are on the [sparse key type](src/sparse.rs).

Both GLWE backends also accept `config.method = BlindRotationMethod::Block` with `SecretKeyDistr::BlockBinary { block_size, occupancy }`. It uses contiguous blocks without mapping or matching; `BlockOccupancy::AtMostOne` stores an independent empty-block dummy after each block's bit controls; `ExactlyOne` stores only the bit controls and requires one `1` per block. Both PBS orders, ManyLUT, MVB and CBS use the same context/evaluator factories. Fourier uses exact native coefficient aggregation followed by ordinary FFT and external products; trace precision remains independent. The [block material contract](src/block.rs) describes import layout and mathematical requirements.

Both modes also work with Classic BR. Secret law is bound to the key; scratch can be reused across modes when its input dimension and gadget layout match.

## Clients and LUTs

For ordinary PBS, `context.try_generate_keys(rng)` returns paired client/server keys. Use the external secret with `context.encryptor`, `pbs_decryptor` or `mvb_decryptor`; public input uses `public_encryptor`. They derive encodings from `config.messages` without receiving a LUT or manual codec. `pbs_lookup_table_compiler()` and `compile_mvb_fn` use the same choices. Family `PbsParameters` also provide client factories without a transform table; `pbs_lookup_table_compiler(messages)` and `compile_mvb_fn(messages, ...)` prepare an ordinary LUT compiler and a coefficient-domain MVB program, with either matching or mixed reducer types.

PBS/ManyLUT returns use Rounded encoding; MVB returns use Scaled. Input, output and subsequent PBS domains must be compatible before feedback. Same-key input/output message overrides are described in [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

Use `encrypt_padded` for front-half programs and `encrypt` for odd full-domain programs. Reuse outputs through `as_mut_view()` and read through `as_view()`; `decrypt_phase` remains available for diagnostics. Family factories check the owning LWE secret's modulus; raw views cannot establish it. `parameters.try_generate_public_key(external_secret, rng)` prepares an LWE public key in the order-dependent external domain; account for its [additional noise](../primus_lwe/README.md#public-key-encryption).

## Boolean and CBS

The Boolean gate wrapper currently requires q=Q and `PbsMessageConfig::new(4)` and ordinary PBS material. The context's Boolean factories take keys without codecs; outputs can be chained under the [shared Boolean contract](../primus_tfhe/README.md#boolean-gates).

For CBS, create a CBS context and call `context.try_generate_circuit_bootstrap_keys(rng)` for `(ClientKey, CircuitBootstrapServerKey)`. Its `server_key()` also supports ordinary PBS. KS→BR uses KS to prepare the CBS input; BR→KS CBS leaves the result in the accumulator ring, while the complete bundle still provides return KS.

`CbsConfig::input_encoding` selects `Padded` (inherits PBS input t) or `MsbBoolean` (t=2, no padding bit). Use `cbs_encryptor` / `cbs_public_encryptor`, then `encrypt` / `encrypt_to`; the client enforces the selected domain. Ordinary `encryptor` keeps PBS encoding. MSB compilation requires exact half gadget weights (even weights for native Q), prepares a centered sign LUT and binds its post-trace corrections. It does not establish a noise budget. See [`CircuitBootstrapLookupTable`](../primus_tfhe/src/lookup_table/circuit_bootstrap.rs) for protection geometry.

Compile identity or a custom function with `compile_cbs_identity`, `compile_cbs_fn` or `compile_cbs_slice`. Bind it with `circuit_bootstrap_evaluator_with_lookup_table`; `circuit_bootstrap_evaluator` is the identity shortcut. Output uses gadget scaling under the ring secret, with no output message codec. CMux requires F to be bit-valued throughout the input domain. Both backends support classic binary/ternary and sparse binary in either order.

`CbsConfig::fourier_trace_precision` retains the CBS trace representation in prepared
parameters. Use `FourierTracePrecision::Ordinary` for NTT or ordinary Fourier;
`Split35` requires native u64, rank one and ring-secret coefficients bounded by one.
The Fourier backend also requires its `split-trace` feature. This selection changes
trace material only; BR and scheme switching remain ordinary. It does not certify
Fourier accuracy or a complete noise margin.

`CbsParameters::br_control_codec()` describes the small-q input to BR, including after input KS/MS. It is not the external input codec for KS→BR; use `context.cbs_encryptor` for that input.

`accumulator_client(client.glwe_secret_key(), t_ring)` prepares Scaled ring candidates independently of the external input modulus. Candidates must share the accumulator secret, Q and encoding. BR decomposition must resolve the LUT and smallest output gadget scale; matching layouts do not prove an adequate error budget. Low-level compatible output-basis overrides are documented on backend `CircuitBootstrapEvaluator`; the recommended workflow and complete examples are in [CBS output and consumption](../primus_tfhe/README.md#cbs-output-and-consumption).

## Features and further reading

Default features are empty; this family does not enable NTT/FFT. `simd` forwards to arithmetic dependencies. Select a concrete backend for evaluation.

[API sources](src/lib.rs) · [Shared operations and encoding](../primus_tfhe/README.md) · [Numerical contracts](../../guides/development/bootstrapping-contracts.md)
