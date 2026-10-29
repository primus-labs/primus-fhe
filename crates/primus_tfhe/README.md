# primus_tfhe

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Shared LWE clients, LUT compilation, encoding contracts, PBS traits and Boolean gates for GLWE and NTRU. Start with a concrete backend's examples for a complete workflow; use this guide to choose operations and their message domains.

## Choosing an operation

Here t is the input message modulus, N the ring length and k the output count. Ordinary PBS uses unsigned Rounded inputs. All `_to` operations reuse caller outputs and evaluator workspace.

| Task | Input domain | Output and main API |
| --- | --- | --- |
| Unary function | Front half `0..ceil(t/2)` | One Rounded LWE; `LookupTable` and `Evaluator` |
| Odd full domain | `0..t`, odd `t>=3` | One Rounded LWE; odd full-domain compiler |
| ManyLUT | One front-half input; `ceil(t/2)<=N/next_power_of_two(k)` | k Rounded LWEs; `InterleavedLookupTable` |
| Factorized MVB | One nonempty front-half prefix | k unsigned Scaled LWEs; prepared program and `FactorizedEvaluator` |
| Bounded two-input function | Same secret/encoding; `x<B`, `y<R`, `B*R<=ceil(t/2)` | One Rounded LWE; `BivariateLookupTable` |
| Boolean gates | Rounded 0/1 with t=4 | Boolean LWE ready for chaining; `BooleanEvaluator` |
| CBS followed by CMux | Padded input or GLWE MSB bits; bit-valued F over the whole domain | GGSW/NGSW control selects an encrypted ring candidate; `CbsEvaluator` |
| One-hot CBS | One padded chunk, t=2M | NLev/NGSW selectors; [NTRU one-hot](../primus_tfhe_ntru/README.md#one-hot-cbs) |
| High-precision lookup | Separately encrypted chunks of uniform width | Independently chosen output chunk count; separate [NTRU LUT repository](../../../primus_high_prec_lut/README.md) |

ManyLUT and MVB compute **several functions of one input**. ManyLUT trades rotation resolution for output count; MVB retains step-one resolution but its factors amplify noise. Scaled numeric flags, Boolean LWEs and gadget controls have different encodings and cannot be interchanged directly.

## Crate map and capabilities

| Family | NTT backend | Fourier backend |
| --- | --- | --- |
| [GLWE parameters and clients](../primus_tfhe_glwe/README.md) | [GLWE NTT](../primus_tfhe_glwe_ntt/README.md) | [GLWE Fourier](../primus_tfhe_glwe_fourier/README.md) |
| [NTRU parameters and clients](../primus_tfhe_ntru/README.md) | [NTRU NTT](../primus_tfhe_ntru_ntt/README.md) | [NTRU Fourier](../primus_tfhe_ntru_fourier/README.md) |

| Blind-rotation mode | PBS / ManyLUT | CBS | Factorized MVB | One-hot / high-precision LUT |
| --- | --- | --- | --- | --- |
| GLWE classic binary/ternary | Both PBS orders | Yes | Yes | Not provided |
| GLWE sparse fixed-weight binary | Both PBS orders | Yes | Yes | Not provided |
| GLWE block binary | Both PBS orders | Yes | Yes | Not provided |
| NTRU classic binary/ternary | Yes | Yes | Yes | Yes |
| NTRU sparse fixed-weight binary | Yes | Yes | Yes | Yes |
| NTRU NTT block binary | Yes | Yes | Yes | One-hot; LUT integration pending |
| NTRU Fourier block binary (u64) | Yes | Yes | Yes | One-hot; LUT integration pending |

All four backends provide secret-key and LWE public-key clients. Fourier supports RustFFT and TFHE-FFT with Native ring moduli only. Example configurations are arithmetic teaching fixtures, without assessed security or failure probability. NTRU's external LWE secret is independent of its ring secret; only the ring secret undergoes invertibility and Fourier inverse-stability screening.

## Selecting blind rotation

All backends re-export `BlindRotationMethod` and select it in `config.method`; changing a secret distribution alone does not select a different algorithm. `Classic` supports binary/ternary, including fixed-weight distributions. Explicit `Sparse { copy_count, bucket_count }` requires fixed-weight binary with `0<h<n`; sparse ternary is unsupported. Matching failure returns an error after retrying the public map, without changing the client secret or falling back to classic.

`SecretKeyDistr::BlockBinary { block_size, occupancy }` samples consecutive independent blocks. `BlockOccupancy::AtMostOne` uniformly selects the zero block or one of its single-`1` states; `ExactlyOne` selects only the single-`1` states. The logical key length must be a nonzero multiple of the block size. `Classic` can use either distribution; `Block` selects direct block aggregation on all four backends. Every bit control is processed, including encrypted zeros. Only `AtMostOne` adds an independently encrypted empty-block dummy; `ExactlyOne` neither stores nor samples it. NTRU Fourier requires u64 and supports ordinary or split BR; trace and SS precision remain independent. Block secrets need their own noise and security assessment. GLWE ring-KS retains the logical LWE prefix followed by public zeros; the padded ring length need not be divisible by the block size.

For ordinary PBS, construct `TfheContext::try_from_pbs_config(config)` and call `context.try_generate_keys(rng)` for `(ClientKey, ServerKey)`. For CBS or NTRU one-hot, use the CBS factory:

```rust,ignore
let context = TfheContext::try_from_cbs_config(config)?;
let (client, server) = context.try_generate_circuit_bootstrap_keys(rng)?;
let mut cbs = context.circuit_bootstrap_evaluator(&server)?;
```

The CBS bundle includes BR, required KS and CBS material. `context.evaluator(server.server_key())?` also binds ordinary PBS to the same keys. Adding CBS to an existing context (GLWE: `try_with_circuit_bootstrap(gadget, input_encoding, fourier_trace_precision)`; NTRU: `try_with_circuit_bootstrap(gadget)`) still requires `try_generate_circuit_bootstrap_keys`, not ordinary key generation. Existing clients can generate ordinary server material through `try_generate_server_key(&client, rng)`; standalone material generation is documented on backend `KeyGenerator` methods.

## Client and server roles

The client keeps secret keys and supplies the server with evaluation keys and input ciphertexts. CBS also receives encrypted ring candidates; NTRU public lifting needs suitable encrypted material. The server compiles public LUTs, evaluates and returns encrypted results. Input/output encodings are public agreements. Each side allocates and reuses its own buffers; examples mark these stages in one process.

Use `client.external_lwe_secret_key()` with context client factories. `context.allocate_lwe_ciphertext()` allocates external LWE storage; `allocate_accumulator_ciphertext()` allocates coefficient-domain ring storage. These allocate zeros, not encryptions. CBS controls use `cbs.allocate_output()` because their layout depends on the gadget basis and transform representation.

Client and evaluator operands use borrowed views: `encrypt_padded_to(message, output.as_mut_view(), rng)`, `decrypt(ciphertext.as_view())` and `apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view())`. ManyLUT/MVB and high-precision batches use slices of preallocated `LweCiphertext<T>` values. Allocate one complete LWE per effective output; LUT padding does not require extra ciphertexts.

## LUTs and resource lifetime

Prepare a reusable compiler with `context.pbs_lookup_table_compiler()?`. It uses the context's configured input/output message domains.

| Program | Function input | Slice input |
| --- | --- | --- |
| Front-half, one output | `compile_fn(function)` | `compile_slice(values)` |
| Front-half, multiple outputs | `compile_interleaved_fn(k, function)` | `compile_interleaved_slice(k, values)` |
| Odd full domain, one output | `compile_odd_full_domain_fn(function)` | `compile_odd_full_domain_slice(values)` |

Front-half compilation programs `D=ceil(t_in/2)` inputs, with output values in `0..t_out`. ManyLUT requires positive k and `D<=N/s`, where `s=next_power_of_two(k)`. A three-output program occupies four slots but returns three ciphertexts. Callbacks receive `(input, output_index)` in input-major order; slices contain D*k values in that order. More outputs reduce input-noise margin. Detailed intervals and rounding are in the [rotation geometry](../../guides/development/bootstrapping-contracts.md#rotation-geometry).

### Choosing the output encoding

`PbsMessageConfig::new(t_in)` defaults to `t_out=t_in`; `.with_output_modulus(t_out)` changes only the output domain. ManyLUT lanes and MVB outputs share that choice. `from_input_bits(4)` selects 16 valid padded inputs with codec modulus 32; its default full output modulus is also 32, so output padding is not implied. Use `try_from_input_bits` for fallible construction or `new(t)` for general/odd moduli.

| Context factory | Input at q | LUT output at Q | Returned-output decoder at q |
| --- | --- | --- | --- |
| `pbs_lookup_table_compiler()` | Rounded | Rounded | `pbs_decryptor` |
| `compile_mvb_fn(domain_len, output_count, function)` | Rounded | Scaled | `mvb_decryptor` |

Both use `context.encryptor(external_secret)` or `public_encryptor(&public)` for input. Clients need no LUT or manual codec. For example, configure `PbsMessageConfig::new(16).with_output_modulus(4)` before constructing the context:

```rust,ignore
let encryptor = context.encryptor(external_secret)?;
let decryptor = context.pbs_decryptor(external_secret)?;
let lut = context.pbs_lookup_table_compiler()?.compile_fn(|x| (x % 4) as u64)?;
let input = encryptor.encrypt_padded(7, &mut rng)?;
let output = evaluator.apply_lookup_table(input.as_view(), &lut);
assert_eq!(decryptor.decrypt(output.as_view())?, 3);
```

The same keys, context and evaluator can serve another output modulus while retaining the input encoding:

```rust,ignore
let messages = context.parameters().messages().with_output_modulus(8);
let decryptor = context.pbs_decryptor_with_message_modulus(external_secret, messages.output_modulus)?;
let compiler = context.pbs_lookup_table_compiler_with_messages(messages)?;
let lut = compiler.compile_fn(|x| (x % 8) as u64)?;
```

To change input messages too, use `context.encryptor_with_message_modulus(external_secret, messages.input_modulus)` or `public_encryptor_with_message_modulus(&public, messages.input_modulus)`. These keep the configured ciphertext modulus, key and noise sampler. The ManyLUT examples show a complete second program using the same evaluator.

For an MVB override, pair `compile_mvb_fn_with_messages(messages, ...)` with `context.ring_return_decryptor(external_secret, messages.output_modulus)` for Scaled output. Compiler and client overrides do not change defaults or existing clients. They do not convert ciphertext encodings or establish a new noise budget. Ciphertexts carry no message-domain metadata: before feedback, ensure the producing output matches the next input's encoding, message modulus and programmed range. A full-domain output may fall outside padded input even when the message moduli agree.

GLWE separates small BR-input q from ring/LUT Q: BR→KS accepts and returns at q, while KS→BR accepts and returns at Q, converting the internal small LWE to q. NTRU uses ring Q and external q: return rescales an existing phase rather than recreating a q-encoding center. Budget Q→q rounding and KS noise, as well as the output codec's recovery condition. MVB remains Scaled even when `t_out=t_in`.

## Encoding and key contracts

| Client method | Message meaning |
| --- | --- |
| `encrypt` | Unsigned value in `0..t` |
| `encrypt_padded` | Same scale, restricted to `0..ceil(t/2)` for front-half LUTs |
| `encrypt_centered` | Representative in `0..t`; upper-half values represent negatives |
| `decrypt` | Canonical representative in the bound output message domain |
| `decrypt_phase` | Undecoded phase for diagnostics |

Centered encryption does not replace the unsigned input contract of ordinary LUTs. A returned value lies in `0..t_out`, while the next front-half PBS accepts only `0..ceil(t_in/2)`. Equal message moduli alone do not permit feedback: encoding, programmed domain and noise margin must all match. Rounded and Scaled have different centers and recovery bounds.

Raw ciphertexts do not record secret identity, encoding or noise. Callers must use paired keys and canonical explicit-modulus coefficients; Fourier keys/evaluators require the same FFT table instance. Shape and LUT checks cannot establish these facts or a security/noise budget. Direct shared-layer client constructors taking `LweSecretKeyRef` also rely on the caller to establish its modulus compatibility; prefer family/context factories with owning keys.

## Boolean gates

Set `config.messages = PbsMessageConfig::new(4)`, then use `boolean_encryptor`, `boolean_public_encryptor`, `boolean_decryptor` and `boolean_evaluator`. Both input and output moduli must be four for gate composition. Clients use unsigned Rounded 0/1 and reject non-Boolean decoded values; ordinary PBS keys suffice.

`evaluate_binary_to` uses one PBS, `not_to` none and `mux_to` two. Outputs retain the external Boolean encoding and can feed subsequent gates. See the complete [GLWE](../primus_tfhe_glwe_ntt/examples/ntt_boolean.rs) or [NTRU](../primus_tfhe_ntru_ntt/examples/ntru_ntt_boolean.rs) example; internal scale restoration is described in the [Boolean contract](src/boolean.rs).

## CBS output and consumption

A CBS context provides `compile_cbs_fn`, `compile_cbs_slice` and `compile_cbs_identity`. They program gadget-scaled `g_j*F(m) mod Q` over the full padded `0..ceil(t_in/2)` domain, or both bits for GLWE `MsbBoolean`; the slice must cover that domain exactly. Bind a program with `circuit_bootstrap_evaluator_with_lookup_table(&server, program)`, or use `circuit_bootstrap_evaluator(&server)` for identity. Compatible functions reuse the same keys. GLWE input uses `context.cbs_encryptor` and `encrypt` / `encrypt_to` for either encoding. MSB Boolean uses t=2 independently of ordinary PBS. NTRU keeps padded inputs through `context.encryptor` / `encrypt_padded`; it does not accept MSB programs.

CBS yields GGSW/NGSW under the accumulator secret. `cmux_to` selects lhs for zero and rhs for one, so **F must be bit-valued over the entire programmed domain**; the input itself need not be a bit. Other canonical ring integers can be consumed by `external_product_to` with their own multiplication/noise budget. Controls must match the basis, actual secret and transform representation; candidate ring ciphertexts must share that secret, modulus and encoding.

Use `context.accumulator_client(ring_secret, t_ring)` for candidates. It encrypts/decrypts N Scaled ring coefficients at accumulator Q; t_ring is independent of input t and gadget scaling. Select it for candidate values and subsequent ring arithmetic. These coefficients are not independent SIMD slots. Reuse the client and its `_to` methods; full examples are [GLWE CBS](../primus_tfhe_glwe_ntt/examples/ntt_circuit_bootstrap.rs) and [NTRU CBS](../primus_tfhe_ntru_ntt/examples/ntru_ntt_circuit_bootstrap.rs).

NTRU `one_hot_evaluator` uses dedicated selector tables. Its `cmux_k_to` consumes nonzero selectors δ₁…δ(M−1) with C0 as default. See the [one-hot contract](../primus_tfhe_ntru/README.md#one-hot-cbs). Explicit numerical combinations use the backend's low-level `CircuitBootstrapEvaluator` / `OneHotCircuitBootstrapEvaluator`; their rustdoc owns resource and alternate-basis contracts.

## Reusing evaluators

Keep the context, keys and compiled programs across requests. An evaluator owns mutable scratch; `_to` methods reuse it and caller outputs. Concurrent workers need separate mutable evaluators/workspaces. Prefer `context.evaluator`, `mvb_evaluator`, `circuit_bootstrap_evaluator` and `one_hot_evaluator` for their respective operations; low-level sharing is documented by the backend APIs.

## Odd full-domain PBS

`compile_odd_full_domain_fn` / `compile_odd_full_domain_slice` program all of `0..t_in`, requiring odd `t_in>=3` and `t_in<=N`. Slices contain t_in outputs in input order. Encrypt with ordinary `encrypt`, then use the existing PBS evaluator and corresponding output decoder.

Folded negacyclic rotation centers must be distinct; collisions return `RotationCenterCollision`. Typical spacing is `N/t_in`, giving about half the front-half input margin. Capacity checks do not establish a failure probability: budget input error and per-coefficient modulus switching. This entry is single-output; interleaved and bivariate compilers retain their front-half contracts. See [rotation geometry](../../guides/development/bootstrapping-contracts.md#rotation-geometry).

## Bounded two-input PBS

`BivariateLookupTable::try_new(B, R, poly_length, input_codec, output_codec, function)` programs `f(x,y)` through `z=x+B*y`. B and R must be positive with `D=B*R<=ceil(t_in/2)`; only that prefix is compiled, with x varying fastest. B need not be a power of two. Output t_out is independent, but both codecs must share one ciphertext modulus: NTRU q≠Q is unsupported here.

Reuse a packed LWE and output; `pack_to` forms `lhs+B*rhs`. Inputs must share the actual secret, unsigned input encoding and modulus, with canonical coefficients and messages in range. The second input's noise is amplified by B; nondivisibility of q by t_in can add encoding-rounding discrepancy. Capacity alone does not prove a sufficient noise margin. See [BivariateLookupTable](src/lookup_table/bivariate.rs) for the complete contract.

## Fixed-scale factorized MVB

`compile_mvb_fn(D, output_count, function)` prepares a nonempty front-half prefix with Rounded input and unsigned Scaled output. The coefficient modulus must be explicit odd, or Native with an **even actual Scaled output scale**; explicit even moduli are unsupported. t_out need not be a power of two. The callback receives `(input, output_index)` with output index outermost.

All outputs share one step-one BR, followed by separate public polynomial products. Output count is positive and unpadded, without reducing input resolution. Integer factor norms amplify BR noise; NTRU factors also amplify encrypted initialization error, and Fourier needs an FFT error budget. Scaled outputs require `mvb_decryptor`; feeding a Rounded-input PBS needs a separate encoding/noise check. Odd full-domain MVB and CBS outputs are not provided.

All four backends support classic and sparse modes, with both GLWE orders. The [GLWE](../primus_tfhe_glwe_ntt/examples/mvb_thresholds.rs) and [NTRU](../primus_tfhe_ntru_ntt/examples/ntru_ntt_mvb_thresholds.rs) examples produce 17 threshold flags. Prefer ManyLUT when its capacity and rotation margin suffice; consider MVB for more outputs with small factor norms. Algebra and noise conditions are in [FactorizedLookupTable](src/lookup_table/factorized.rs) and the [MVB design](../../guides/development/bootstrapping-contracts.md#factorized-mvb).

## Error boundaries

Use `try_*` configuration/binding factories and handle their returned error types. `LookupTableError` covers compilation, `TfheEvaluationError` evaluator binding, `ClientError` ordinary client operations and `BooleanError` Boolean operations. Shape failures may panic as documented on each operation. Underlying causes remain available through `std::error::Error::source()`.

## Features and further reading

Default features are empty; `simd` forwards to arithmetic dependencies. Choose a concrete backend for homomorphic evaluation.

[API sources](src/lib.rs) · [Parameter conditions](../../guides/development/tfhe-parameters.md) · [Numerical contracts](../../guides/development/bootstrapping-contracts.md)
