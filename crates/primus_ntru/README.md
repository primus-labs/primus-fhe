# primus_ntru

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time. No recommended security parameters are provided.

Scalar secret-key NTRU encryption and evaluation over `Z_q[X]/(X^N + 1)`. NTT uses an explicit field modulus.

## Quick start

This u64 NTT example shows both ordinary messages and encoded/phase primitives. The calling crate directly depends on `primus_ntru` with `ntt` enabled, plus `primus_ntt`, `primus_poly`, `primus_modulus`, `primus_encoding` and `rand`. N=32 is a small functional fixture, not a security parameter.

```rust
use primus_encoding::PlaintextEmbedding;
use primus_modulus::BarrettModulus;
use primus_ntru::{NtruParameters, NttNtruSecretKey, SecretKeyDistr};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;

let poly_length = PolyLength::new(32);
let modulus = BarrettModulus::new(132_120_577u64);
let table = U64NttTable::new(poly_length, modulus).unwrap();
let params = NtruParameters::new(poly_length, 16, modulus, SecretKeyDistr::SparseTernary, 0.7);
let mut rng = rand::rng();
let (_coeff_secret, secret) =
    NttNtruSecretKey::generate_pair(params.encryption_parameters(), &table, &mut rng).unwrap();
let message = Polynomial::new(vec![3u64; poly_length.get()]);
let embedding = PlaintextEmbedding::Unsigned;

// Ordinary messages: the adapter uses the parameter codec.
let mut ciphertext = secret.encrypt_message(&message, &params, embedding, &table, &mut rng);
assert_eq!(
    secret.decrypt_message(&ciphertext, &params, &table),
    message
);

// Both the encoded input and the extracted phase are coefficient polynomials.
let codec = params.plaintext_codec();
let mut encoded = Polynomial::new(vec![0; poly_length.get()]);
codec.encode_slice_to(message.as_ref(), encoded.as_mut(), embedding);
secret.encrypt_encoded_to(
    &encoded,
    &mut ciphertext,
    params.encryption_parameters(),
    &table,
    &mut rng,
);
let mut phase = Polynomial::new(vec![0; poly_length.get()]);
secret.decrypt_phase_to(&ciphertext, &mut phase, modulus, &table);
let mut decoded = vec![0; poly_length.get()];
codec.decode_slice_to(phase.as_ref(), &mut decoded);
assert_eq!(decoded, message.as_ref());
```

Use `encrypt_message_to` to reuse ciphertext storage without a separate encoded polynomial. Keep parameters, tables, keys and output across requests.

## Ciphertext semantics

Let `f` be the invertible secret, `mu` an encoded message and `g_l` a gadget scalar. These phases omit application-specific plaintext encoding:

| Type | Phase of coefficient row `c_l` |
| --- | --- |
| NTRU | `f*c = mu + e` |
| NLev of `m` | `f*c_l = g_l*m + e_l` |
| NGSW of `m` | `f*c_l = g_l*f*m + e_l` |

NLev and NGSW store the same number of rows but have different roles. `NLev[1]` can lift a public coefficient polynomial to encrypted NTRU through an external product; `NGSW[1]` preserves an already encrypted message. Copying a message to `c` is not a general trivial NTRU encryption.

## Parameters and keys

| Parameters | Purpose |
| --- | --- |
| `NtruParameters` | Ordinary encryption/decryption with a `ScaledCodec` |
| `NtruEncryptionParameters` | Ring and samplers for key generation and encoded/zero encryption; no codec |
| `NlevParameters` | Encryption parameters and gadget decomposition; no plaintext codec |

Use `NtruParameters::try_new` for ordinary messages. Given ordinary parameters, `NlevParameters::try_with_ntru_params(&ntru_params, decomposition)` takes a `DecompositionConfig` and derives gadget parameters in the same ring, reusing the prepared samplers; `try_with_basis` accepts an already prepared basis. Gadget-only construction is documented on [NlevParameters](src/parameter/gadget.rs).

Construct [PolyLength](../primus_shape/README.md#polynomial-length) once and reuse it for parameters, tables and workspaces. Fixed secret weights must fit N. Parameter checks cover encoding and sampling, not secret invertibility, transform availability or a noise/security budget.

Pass `encryption_parameters()` to `NttNtruSecretKey::generate_pair`. The returned signed coefficient secret generates evaluation keys; the transformed secret supports encryption and phase extraction. `try_from_coeff_secret_key` converts an existing secret and can reject it. NTT import requires signed coefficient magnitudes below q. Keep the construction representation: matching q/N does not prove NTT roots, evaluation order or secret identity.

NTT generation rejects zero evaluations. Bounded rejection sampling can fail; attempt counts and inversion routines are not promised constant time. An unsuccessful candidate search returns `KeyGenerationExhausted`. Accepted secrets follow the proposal distribution **conditioned on backend acceptance**; `distr()` records the proposal.

General NTRU supports nonbinary ring secrets. NTRU TFHE uses an independent external LWE secret for binary/ternary blind-rotation controls, without requiring a zero-padded binary ring secret.

Secret keys and private encryption/generation/decryption workspaces erase owned buffers on drop. Discard an explicitly zeroized secret key. Caller-owned plaintext and phase outputs retain their own lifetimes.

The [automorphism example](examples/automorphism.rs) shows key generation and reusable NTT evaluation under the original secret:

```sh
cargo run -p primus_ntru --example automorphism --features ntt
```

## Encryption and decryption

| Method | Input or result |
| --- | --- |
| `encrypt_message` / `encrypt_message_to` | Message in `[0, t)` and explicit `PlaintextEmbedding`; allocate / overwrite transformed ciphertext |
| `encrypt_encoded_to` / `encrypt_zeros_to` | Encoded coefficients / zero polynomial to transformed ciphertext, without plaintext scaling |
| `decrypt_phase_to` | Coefficient-domain `f*c`, without decoding |
| `decrypt_message` / `decrypt_message_to` | Decoded coefficient polynomial; allocate / overwrite output |

Message methods take `NtruParameters`; encoded/zero encryption takes `NtruEncryptionParameters`. Both `Unsigned` and `Centered` embeddings accept canonical residues in `[0, t)`; centered `t-1` represents `-1`. Both use the same decoder. Decoded values retain coefficient type `T`.

NTT secret-key operations need no workspace. Encoded NTT inputs must be canonical coefficients at q. Match key, parameters, table and output; invalid plaintext values can fail after partial writes or randomness consumption. See the [secret-key methods](src/secret_key) for exact buffer and failure contracts.

For [phase-error diagnostics](../primus_encoding/README.md#phase-error-diagnostics), compare the phase with the **expected message** encoded using the actual codec and embedding. Decoding and re-encoding is not an independent reference.

## Gadget and evaluation primitives

| Operation | Input and output |
| --- | --- |
| `encrypt_nlev_to` / `encrypt_ngsw_to` | Ring polynomial to transformed gadget rows, without plaintext codec scaling |
| `encrypt_nlev_constant_to` | Ring constant to transformed NLev |
| `encrypt_ngsw_signed_constant_batch_to` | Signed constants to consecutive transformed NGSWs |
| `NttNtruKeySwitchingKey` | Coefficient NTRU under an input secret to coefficient NTRU under an output secret |
| Automorphism `apply_to` | Coefficient NTRU under the original secret after `X -> X^d` |
| Automorphism `apply_ntt_to` | Corresponding transformed input and output |

Evaluation keys retain their decomposition bases; construct matching workspaces once and reuse them. Automorphism requires odd `d` in `[1, 2N)`. NLev rows can each use scalar automorphism, but applying it row-wise to NGSW does **not** preserve the NGSW message/key relation.

`NttNlev::lift_monomial_to` fuse public-polynomial lifting with the first binary/ternary rotation. Supply NLev[1], a positive NLev bit and an optional negative NLev bit; a zero exponent still performs the lift. Subsequent ternary `cmux_ternary_monomial_to` uses positive/negative NGSW bits, which must be mutually exclusive. Exponents are already quantized into `0..2N`. Reuse `NttNtruCmuxWorkspace::new(poly_length, levels)`.

Sample extraction, external products, lift and CMUX are documented in [`primus_lattice`](../primus_lattice/README.md).

## Independent LWE return

`NtruLweKeySwitchingKey::generate(f, Q, s, &parameters, rng)` prepares return from NTRU secret f at Q to an independent `LweSecretKey` s at q. Prepare `parameters` with `primus_lwe::LweKeySwitchingParameters::try_new(output, basis)`, which binds codec-free target LWE encryption state and a basis at q; source Q remains separate. The output dimension may differ from N; s need not extend to an invertible NTRU secret. Each signed coefficient of f must have magnitude below an explicit q.

Inputs are coefficient-domain NTRU ciphertexts; recover transformed outputs to coefficients first. Bind the key and target modulus with `LweReturnEvaluator::new(&key, q_modulus)`, then allocate only the scratch needed below and reuse it. All paths overwrite outputs without online allocation or a transform dependency.

| Requested results | Evaluator methods | Workspace constructor |
| --- | --- | --- |
| One coefficient | `return_at_to` | `new_scalar_workspace()` |
| Coefficients from one NTRU | `return_many_at_to` / `return_prefix_to` | `new_batch_workspace()` |
| Coefficients of successive NTRUs | Workspace `begin_batch`, evaluator `append_at`, then `return_batch_to` | `new_batch_workspace()` |

Shared-input returns reuse one Q→q conversion. `return_many_at_to` preserves arbitrary index order and repeats; `return_prefix_to` selects `0..outputs.len()`. Empty requests write nothing, and singleton requests use the scalar path.

`LweReturnBatchWorkspace` tracks the valid prefix of a stream. Each append releases the source borrow; submit exactly the appended count, up to `batch_capacity()`. Finish or discard the stream before shared-input returns or reuse with another binding. Workspace state does not establish key identity: all appends and submission must use the same actual secrets and Q/q. See [LweReturnEvaluator](src/key_switch/lwe/evaluator.rs) for state and failure contracts. Intermediate slots are internal; callers cannot submit unprepared samples.

The operation first computes `c' = round(q*c/Q) mod q` coefficient-wise (nearest, ties upward), then extracts under f and key-switches at q. The extracted phase is `b-<a,f> = (f*c')[index]`. **Rounding precedes extraction negation**; reversing them changes half-tie results. See [LweReturnEvaluator](src/key_switch/lwe/evaluator.rs) for the mask layout.

Q and q may be native or explicit, including equal moduli. Returns keep the coefficient type (u32→u32 or u64→u64); reducing q does not narrow the word. Inputs must be canonical at Q. Budget f-weighted rounding, secret-weighted decomposition error and LWE key noise, plus previous NTRU error. Scaling an encoded message from Q to q is not generally identical to freshly encoding at q.

## Trace, projection and expansion

`NttNtruTraceKey` operate on coefficient ciphertexts under the original secret. Let `M` be the input message; target messages below omit evaluation noise.

| Method | Target message |
| --- | --- |
| `apply_to` / `apply_reverse_to` | Constant `N*M[0]` / `M[0]` |
| `apply_partial_to(input, r, ...)` | `d * sum_j M[j*d] X^(j*d)`, where `d=N/r` |
| `apply_reverse_partial_to(input, r, ...)` | `sum_j M[j*d] X^(j*d)` |
| `project_coefficient_to` / `project_coefficients_to` | Constant `M[index]` / constants in selection order |
| `project_prefix_coefficients_to(input, count, ...)` | First `count` coefficients as constants; no zero-tail assumption |
| `expand_coefficients_to` | All N coefficients as constants |
| `expand_partial_coefficients_to(input, count, ...)` | First `count` constants, assuming a zero message tail |

Partial trace accepts a power-of-two r in `1..=N`; r=N copies input and r=1 is full trace. Reverse trace normalizes before each automorphism/addition. Normalization uses `2^-1 mod q`. The [trace methods](src/trace) document the error terms.

Projection accepts arbitrary indices, including duplicates and an empty selection; prefix projection accepts any count in `0..=N`. Each selected coefficient needs a full reverse trace, even for count one. Partial expansion instead requires a power-of-two count in `1..=N`; count one copies the input and count N gives full expansion. It normalizes once and has different error behavior from projection.

Partial expansion produces constants only when **message** coefficients `count..N` are zero. Otherwise output i targets `sum_j M[i+j*count] X^(j*count)`. Ciphertext/noise tails need not vanish; all outputs retain ring length N.

## Same-secret scheme switching

`NttNtruSchemeSwitchKey` convert coefficient `NLev_f[m]` to transformed `NGSW_f[m]`. `key_basis` controls decomposition; the independent `output_basis` specifies input/output gadget scalars and level count. Inputs must already use that output basis; matching lengths alone cannot establish this. Reuse a matching external-product workspace.

The evaluation material is `NGSW_f[f]`. Input errors are multiplied by f, decomposition errors by f², and key errors also contribute. Publishing this secret-dependent material requires a justified key-dependent-message/circular-security assumption and suitable parameters; functional correctness provides neither a security proof nor a CBS parameter recommendation. A bit-valued m can control CMUX. See [scheme switching](src/scheme_switch) for the full phase contract.

For packed coefficients that only need NGSW output, [`NttNtruProjectionKey`](src/scheme_switch/projection.rs) accepts an explicit `NtruProjectionMethod`: `Separate` (the enum default), `FusedLastStage`, `FusedLastThreeStages`, or `PairedTrace`. The last method pairs reverse-trace stages and fuses the remaining two or three with SS. `project_to` accepts general message tails; allocate its reusable buffer with `scratch_len()` (2N, 2N, 8N, or 5N/8N respectively, with paired size depending on even/odd log₂N). Only the selected fusion material is generated. Fused strategies change decomposition residuals and key errors; switching strategies requires a new noise budget. Borrow the owned ordinary trace/SS keys for NLev or dual outputs.

## Features

Default features are empty; the NTRU-to-LWE return path needs no transform backend. `ntt` enables NTT operations. `simd` forwards to active arithmetic dependencies without enabling a transform backend.

Tests, examples and benchmarks declare `required-features`; Cargo skips an entire target when these are missing. Select the features shown by its run command.

## Further reading

See [API sources](src) for method contracts, [benchmarks](benches/README.md) for workloads and run commands.

## License

Licensed under either [Apache-2.0](../../LICENSE-APACHE-2.0) or [MIT](../../LICENSE-MIT), at your option.
