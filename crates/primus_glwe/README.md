# primus_glwe

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Single-modulus GLWE keys and operations, with separate NTT and native-torus Fourier representations. Here `k` is the GLWE dimension and `N` the polynomial length.

## Quick start

This u64 NTT example shows both ordinary messages and encoded/phase primitives. The calling crate directly depends on `primus_glwe` with `ntt` enabled, plus `primus_ntt`, `primus_poly`, `primus_modulus`, `primus_encoding` and `rand`. N=32 is a small functional fixture, not a security parameter.

```rust
use primus_encoding::PlaintextEmbedding;
use primus_glwe::{GlweDimension, GlweParameters, NttGlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;

let poly_length = PolyLength::new(32);
let modulus = BarrettModulus::new(132_120_577u64);
let table = U64NttTable::new(poly_length, modulus).unwrap();
let params = GlweParameters::new(
    GlweDimension::new(1),
    poly_length,
    16,
    modulus,
    SecretKeyDistr::UniformBinary,
    0.7,
);
let mut rng = rand::rng();
let (_coeff_secret, secret) = NttGlweSecretKey::generate_pair(
    params.size(),
    params.encryption_parameters(),
    &table,
    &mut rng,
);
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

Use `encrypt_message_to` to reuse ciphertext storage without a separate encoded polynomial. Keep parameters, tables, keys and output across requests; Fourier operations also reuse an FFT engine and workspaces.

## Parameters and keys

| Parameters | Purpose |
| --- | --- |
| `GlweParameters` | Ordinary encryption/decryption with a `ScaledCodec` |
| `GlweEncryptionParameters` | Modulus and samplers for key generation and encoded/zero encryption; no codec or layout |
| `GlevParameters` / its alias `GgswParameters` | GLWE layout, encryption parameters and gadget decomposition; no plaintext codec |

Use `GlweParameters::try_new` for ordinary messages, or `GgswParameters::try_new(size, modulus, secret_distr, decomposition, sigma)` for gadget-only work. Here `size` is a `GlweSize`, `decomposition` a `DecompositionConfig`, and `sigma` is in coefficient units. With ordinary parameters already prepared, `GlevParameters::try_with_glwe_params(&glwe_params, decomposition)` derives gadget parameters in the same ring, reusing the prepared samplers.

Construct [PolyLength](../primus_shape/README.md#polynomial-length) once and reuse it for parameters, tables and workspaces. GLWE dimensions use `GlweDimension`; fixed secret weights apply to all `k*N` coefficients, not separately to each polynomial. Fallible constructors report invalid layouts, encoding or sampling configurations; they do not establish transform availability or a noise/security budget.

| Key | Representation and role |
| --- | --- |
| `GlweSecretKey<T>` | Signed coefficients; sampling and evaluation-key generation |
| `NttGlweSecretKey<T>` | Canonical NTT residues modulo `q`; NTT encryption/decryption |
| `FourierGlweSecretKey` | Integer-scaled Fourier secret for decryption |
| `FourierGlweEncryptor` | Borrows a coefficient secret and prepares exact native encryption/key generation |
| `NttGlwePublicKey<S>` | NTT encryption of zero; public-key encryption |

NTT's `generate_pair` returns coefficient and transformed secrets. For Fourier, generate a `GlweSecretKey` with the parameter sampler, then prepare `FourierGlweEncryptor::try_new(&secret, params.encryption_parameters())`. Prepare `FourierGlweSecretKey::from_coeff_secret_key(&secret, fft)` only when decryption is needed. The encryptor borrows the coefficient secret; keep it alive for all uses.

Keep the construction representation: matching modulus and length does not prove NTT roots, evaluation order or secret identity. `NttGlweSecretKey::new` checks imported layout, while canonicality, distribution and transform provenance remain caller obligations. Raw public-key bytes use native endianness and contain no parameter metadata. Secret buffers are erased on drop; discard a key after explicit zeroization.

## Encryption and decryption

For secret polynomials `s_i`, the GLWE phase is `b - sum_i a_i*s_i = Encode(m) + e`.

| Method | Input or result |
| --- | --- |
| `encrypt_message` / `encrypt_message_to` | Message in `[0, t)` and explicit `PlaintextEmbedding`; allocate / overwrite ciphertext |
| `encrypt_encoded_to` | Already encoded coefficient polynomial; no plaintext scaling |
| `encrypt_zeros` / `encrypt_zeros_to` | Zero polynomial; allocate / overwrite ciphertext |
| `decrypt_phase_to` | Coefficient-domain phase, without decoding |
| `decrypt_message` / `decrypt_message_to` | Decoded coefficient polynomial; allocate / overwrite output |

Message methods take `GlweParameters`; encoded/zero encryption and public-key generation take `GlweEncryptionParameters`. Both `Unsigned` and `Centered` embeddings accept canonical residues in `[0, t)`; centered `t-1` represents `-1`. Both use the same decoder. Decoded values retain coefficient type `T`.

NTT secret-key operations need no workspace. Fourier encryption uses the prepared encryptor without an extra workspace argument; decryption uses `FourierGlweDecryptWorkspace`. NTT public encryption uses `NttGlwePublicEncryptWorkspace<T>`. Reuse these resources and erase caller-owned plaintext/phase buffers according to their own lifetimes. The encryptor checks the declared sampler support once and owns erased exact-product caches and one coefficient row. For arbitrary imports, `FourierGlweEncryptor::from_coeff_secret_key` uses the full signed word bound; u64 then requires expensive O(kN²) schoolbook multiplication.

NTT also provides `encrypt_message_coeff_to`, `decrypt_phase_coeff_to` and `decrypt_message_coeff_to` for coefficient ciphertexts. Their last argument is an N-element scratch slice that need not be cleared before the call. Encryption leaves secret-dependent products there; use an erasing owner such as `zeroize::Zeroizing<Vec<T>>`.

Encoded NTT inputs must be canonical coefficients in `[0, q)`. Match key, parameter, table and output layouts; Fourier values must use the exact FFT table instance from key generation. Invalid plaintext values can fail after partial writes or randomness consumption. See the [secret-key](src/secret_key) and [public-key](src/public_key) methods for precise buffer and failure contracts.

For [phase-error diagnostics](../primus_encoding/README.md#phase-error-diagnostics), compare the phase with the **expected message** encoded using the actual codec and embedding. Decoding and re-encoding is not an independent reference.

Fourier key generation completes each row and gadget diagonal exactly in the native ring before floating-point conversion; ordinary u64 conversion error still needs a noise budget. Regenerate material produced by the former unreduced Fourier-product path. If it was disclosed, replace the affected secrets: converting published rows cannot undo disclosure. See `FourierGlweEncryptor` rustdoc for exact support and preparation contracts.

## Gadget ciphertexts

`encrypt_glev_to` and `encrypt_ggsw_to` apply gadget scaling to coefficient-domain ring polynomials without ordinary plaintext encoding. A GGSW control bit is the constant polynomial `0` or `1`. For NTT, construct the gadget workspace from `GadgetSize`: GLev needs its polynomial length; GGSW also needs its level count. Fourier reuses the same encryptor across gadget bases and level counts, completing native row diagonals before FFT.

`encrypt_ggsw_constant_batch_to` writes consecutive transformed GGSWs: `input.len() * params.ggsw_len()` residues for NTT, or `input.len() * params.fourier_ggsw_len()` complex values for Fourier. NTT constants must be canonical at q; Fourier constants use native-ring values. Both backends also provide `encrypt_ggsw_constant_batch_coeff_to` for coefficient output; Fourier writes exact native rows directly without FFT scratch or inverse rounding. `encrypt_message_coeff_to` similarly writes ordinary coefficient ciphertexts.

## Evaluation primitives

| Evaluation key | Operation |
| --- | --- |
| `NttGlweKeySwitchingKey` / `FourierGlweKeySwitchingKey` | Change GLWE secret and optionally dimension, keeping the ring length and modulus |
| `NttGlweAutomorphismKey` / `FourierGlweAutomorphismKey` | Apply `X -> X^d` for odd `d` in `[1, 2N)`, returning under the original secret |
| `NttGlweSchemeSwitchKey` / `FourierGlweSchemeSwitchKey` | Convert coefficient GLev to transformed GGSW under the same secret |

Prepare `GlweKeySwitchingParameters::new(input_dimension, output_glev)` and pass the complete parameters to either key-switching key’s `generate` method. The input secret must match the declared rank and polynomial length; `output_glev` supplies the target layout, decomposition and row-encryption noise. Fourier generation takes the target encryptor instead of a transformed secret and separate gadget workspace.

Evaluation keys retain their layouts and decomposition bases. Construct the matching workspace once and reuse it. Automorphism provides coefficient `apply_to` and transformed `apply_ntt_to` / `apply_fourier_to`; direct Fourier output can round differently from a coefficient roundtrip.

[Scheme switching](src/scheme_switch) uses matching coefficient/transformed secrets for NTT generation, or one target encryptor for Fourier generation. Fourier automorphism and trace generation also take only the prepared target, deriving their secret messages internally. Output gadget scaling is inherited from the input GLev; `key_basis()` controls decomposition and may differ from the output basis. Supply an external-product workspace matching `key.key_size()`.

Rank-one NTT scheme switching stores only a square `GLev(s²)` and computes each mask row as `sum D(a) GLev(s²) + (b,0)`, reusing the transformed body row. Higher ranks and Fourier retain the full `GGSW(-s_i)` products. The square construction removes body decomposition and its key-error terms; input-error propagation and square-secret residuals remain, so it does not guarantee lower noise for every input. Trace and scheme switching remain separate operations.

## Trace, projection and expansion

`NttGlweTraceKey` and `FourierGlweTraceKey` operate on coefficient ciphertexts. Let `M` be the input message; target messages below omit evaluation noise.

| Method | Target message |
| --- | --- |
| `apply_to` / `apply_reverse_to` | Constant `N*M[0]` / `M[0]` |
| `apply_partial_to(input, r, ...)` | `d * sum_j M[j*d] X^(j*d)`, where `d=N/r` |
| `apply_reverse_partial_to(input, r, ...)` | `sum_j M[j*d] X^(j*d)` |
| `project_coefficient_to` / `project_coefficients_to` | Constant `M[index]` / constants in selection order |
| `project_prefix_coefficients_to(input, count, ...)` | First `count` coefficients as constants; no zero-tail assumption |
| `expand_coefficients_to` | All N coefficients as constants |
| `expand_partial_coefficients_to(input, count, ...)` | First `count` constants, assuming a zero message tail |

With `split-trace`, `SplitFourierGlweTraceKey::generate` reuses a prepared `FourierGlweEncryptor` and provides extra-precision prefix projection for native u64, rank-one secrets with coefficients in `{-1,0,1}`. Allocate its matching workspace with `key.new_workspace()`. Exact coefficient key generation uses auxiliary NTT/CRT, while evaluation retains only low35/high29 Fourier spectra. Trace payload and inverse transforms double; this is an explicit precision/cost tradeoff, not a noise-budget guarantee. See the [split trace contract](src/trace/split.rs).

Partial trace accepts a power-of-two `r` in `1..=N`, retaining equally spaced positions in one GLWE. `r=N` copies the input; `r=1` is full trace. Reverse trace normalizes before each automorphism/addition: NTT multiplies by `2^-1 mod q`, while Fourier uses unsigned coefficient `floor(x/2)`. The NTT field operation does not inherit the torus RevHomTrace noise bound.

Projection accepts arbitrary indices, including duplicates and an empty selection; prefix projection accepts any count in `0..=N`. Each selected coefficient needs a full reverse trace, even for count one. Partial expansion instead accepts a power-of-two count in `1..=N`: count one copies the input and count N gives full expansion. It normalizes once, so its error behavior differs from projection.

For partial expansion to produce constants, **message** coefficients `count..N` must be zero. Otherwise output i targets `sum_j M[i+j*count] X^(j*count)`. Ciphertext/noise tails need not vanish. All outputs retain ring length N; detailed normalization and workspace contracts are on the [trace methods](src/trace).

## LWE packing

Choose packing by the input secret and required coefficient positions. Both paths require the same input/output modulus and message encoding; zero target-message positions may still contain noise.

| Path | Input secret and count | Target message |
| --- | --- | --- |
| Trace key `pack_lwe_to` / `pack_lwes_to` | Flattened GLWE secret of dimension `k*N`; power-of-two count p in `1..=N` | `sum_i m[i] X^(i*N/p)`; adjacent slots only at p=N |
| `NttLwePackingKeySwitchingKey` / `FourierLwePackingKeySwitchingKey` | Independent LWE secret; any count p in `1..=N` | `key_switch_to`: one constant; `pack_lwes_to`: `sum_i m[i] X^i` |

Trace packing follows [RevHomTrace](https://github.com/Stirling75/RevHomTrace/blob/main/src/glwe_conv_rev.rs). A batch uses `NttGlwePackingWorkspace::new(size, p)` or the Fourier counterpart for a fixed p; single-LWE packing uses a trace workspace.

Independent-key packing accepts an input dimension different from `k*N`. Generate its key from the input `LweSecretKeyRef`, output GLWE secret and GLev parameters, then reuse a GLWE key-switching workspace for the output layout. Batch counts can vary. Budget input noise, secret-weighted decomposition error and key noise, plus Fourier error. See [packing key switching](src/packing_key_switch) for complete layout and buffer contracts.

## Features

Default features are empty. `ntt` enables NTT operations; `fourier` enables ordinary Fourier APIs and the internal auxiliary NTT/CRT dependency for coefficient key generation, without selecting an FFT engine or enabling the NTT GLWE API. Use `rustfft` or `tfhe-fft` to enable Fourier with a concrete engine; both can coexist. Add `split-trace` for Split35 keys, for example `--features rustfft,split-trace`. `simd` forwards to active arithmetic dependencies without enabling a transform backend.

Tests, examples and benchmarks declare `required-features`; Cargo skips an entire target when these are missing. Select the features shown by its run command.

## Further reading

See [API sources](src) for method contracts, [benchmarks](benches/README.md) for workloads and run commands, and the workspace [testing guide](../../guides/development/testing.md) for validation commands.
