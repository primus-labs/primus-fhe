# primus_lwe

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Single-modulus LWE key generation, secret-key and public-key encryption, and key switching for Primus FHE. Ciphertext storage and arithmetic come from [`primus_lattice`](../primus_lattice/README.md); message encoding uses [`RoundedCodec`](../primus_encoding/README.md).

## APIs

Public types are exported at the crate root.

| Type | Role |
| --- | --- |
| `LweConfig<M>` | Constant numerical description, converted into prepared encryption parameters with `TryFrom` |
| `LweEncryptionParameters<T, M>` | Ciphertext domain and prepared samplers, without a message codec |
| `LweParameters<T, M>` | Dimension, moduli, plaintext codec, secret distribution and precomputed samplers |
| `LweSecretKey<T>` | Owned encoded coefficients; message, encoded and phase operations |
| `LweSecretKeyRef<'a, T>` | Borrowed `Encoded` or `Signed` coefficients; raw single-ciphertext operations |
| `LwePublicKey<T>` | Square-matrix Lindner–Peikert-style public-key encryption |
| `LweKeySwitchingParameters<T, M>` | Target encryption state and matching decomposition basis |
| `LweKeySwitchingKey<T>` | Switches the secret key and optionally the dimension, under the same ciphertext modulus |
| `LweCiphertext<T>` | Alias for `primus_lattice::lwe::Lwe<Vec<T>>` |
| `MultiMsgLweCiphertext<T>` | Alias for `primus_lattice::lwe::MultiMsgLwe<Vec<T>>` |

`encrypt_message` / `encrypt_message_batch` take an explicit `PlaintextEmbedding` and allocate output. Their `_to` variants overwrite caller-owned storage without allocating. Secret-key decryption accepts owned or borrowed ciphertexts. Public-key ciphertexts use the same decoder and key switch.

## Quick start

Start with message encryption/decryption; use the primitives when choosing the encoding separately or inspecting phases. These small parameters demonstrate the API, not security. The calling crate directly depends on `primus_lwe`, `primus_modulus`, `primus_encoding` and `rand`.

```rust
use primus_encoding::PlaintextEmbedding;
use primus_lwe::{LweDimension, LweParameters, LweSecretKey, SecretKeyDistr};
use primus_modulus::NativeModulus;

let params = LweParameters::new(
    LweDimension::new(64),
    4u64,
    NativeModulus::new(),
    SecretKeyDistr::UniformBinary,
    0.7,
);
let mut rng = rand::rng();
let secret = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
let embedding = PlaintextEmbedding::Unsigned;
let message = 3;

// Ordinary messages: the adapter uses the parameter codec.
let mut ciphertext = secret.encrypt_message(message, &params, embedding, &mut rng);
assert_eq!(secret.decrypt_message(&ciphertext, &params), message);

// Encoded primitives: choose the encoding separately and reuse the ciphertext.
let codec = params.plaintext_codec();
let encoded = codec.encode_value(message, embedding);
secret.encrypt_encoded_to(
    encoded,
    &mut ciphertext,
    params.encryption_parameters(),
    &mut rng,
);
let phase = secret.decrypt_phase(&ciphertext, params.cipher_modulus());
assert_eq!(codec.decode_value(phase), message);
```

[examples/basic.rs](examples/basic.rs) extends this to public keys, independent batches and key switching: `cargo run -p primus_lwe --example basic`. Reuse keys and parameters across requests, and use `encrypt_message_to` / `encrypt_encoded_to` to reuse output.

## Parameters and encoding

`LweConfig<M>` stores the dimension, a `primus_modulus::ModulusConfig<M>`, secret distribution and coefficient-noise standard deviation. Use `LweEncryptionParameters::try_from(config)` to validate the modulus and prepare samplers once. `LweConfigError` distinguishes modulus configuration failures from `LweParameterError`; direct parameter constructors remain available when the modulus is already prepared.

Use `LweParameters`, which includes a `RoundedCodec`, for ordinary messages; use codec-free `LweEncryptionParameters` for already encoded data. Pass `params.encryption_parameters()` to secret-key generation and owned `encrypt_encoded[_to]`. `decrypt_phase` takes a ciphertext and modulus and returns `b - <a,s>` without decoding.

`LweDimension::try_new(n)` checks nonzero `n` and representable `n+1`; use `.ciphertext_len()` for allocation. `LweParameters::try_new` checks encoding, secret-distribution and noise conditions, returning `LweParameterError`; `new` panics on the same errors. Require `t >= 2`, `q > t`, and fixed secret weights no greater than `n`. `NativeModulus<T>` denotes `q = 2^T::BITS`, for which `cipher_modulus_value()` returns `None`; explicit moduli return `Some(q)`. Noise standard deviation is measured in ciphertext coefficient units.

Message inputs and decoded outputs are `T` residues in `[0,t)`. `PlaintextEmbedding::Centered` also takes unsigned residues, with `t-1` representing `-1`; both embeddings use the same `decrypt_message`. Secret-key encryption satisfies `b = <a,s> + e + Encode(message) mod q`; phase noise must remain within the codec's decoding margin.

Keys, ciphertexts and parameters must share the dimension and modulus, and encoded coefficients must be canonical. Owning keys check their recorded modulus; `LweSecretKey::new(coefficients, distribution, modulus)` also requires imports to satisfy the declared distribution, without checking these coefficient conditions. Secret coefficients are erased on drop; discard a key after explicit `zeroize()`.

`as_view()` carries no modulus metadata, so check the owning key's modulus before using raw APIs. Borrowed `encrypt_encoded[_to]` takes an encoded residue, modulus, uniform/noise samplers and RNG; the samplers must use that same modulus. `LweSecretKeyRef::Signed` borrows signed coefficients without a converted copy: explicit moduli require `-q < s_i < q`, while Native accepts every signed value. Raw views allow dimension zero.

For noise diagnostics, encode the **expected message** with the actual codec and embedding, then compare it with the extracted phase using [`phase_error_magnitude`](../primus_encoding/README.md#phase-error-diagnostics). This returns a circular distance; re-encoding the decoded message can hide incorrect decryption.

## Public-key encryption

`LwePublicKey::generate(secret, dimension, modulus, uniform, noise, rng)` accepts a `LweSecretKeyRef` and prepared samplers. Pass `secret.as_view()` for an owned key or `LweSecretKeyRef::Signed` for signed coefficients, after establishing the secret and sampler modulus contracts above.

Message encryption uses `encrypt_message[_to]` with `LweParameters` and an explicit embedding; encoded encryption uses `encrypt_encoded[_to]` with the modulus, noise sampler and RNG. The resulting ciphertexts use the same secret-key decoder and key switch.

The public key stores `n` rows `[A_i, b_i]`, totaling `n*(n+1)` coefficients, with `b = A s + e`. Encryption samples independent ternary coefficients `r` with `Pr[0] = 1/2`, `Pr[-1] = Pr[1] = 1/4`, plus fresh Gaussian noise `e1, e2`:

```text
a = A^T r + e1
c = b^T r + e2 + Encode(message)
phase = Encode(message) + e^T r + e2 - e1^T s  (mod q)
```

The encryption noise sampler describes `e1` and `e2`, not the total noise. Parameters must account for long-term and ephemeral secret security, all noise terms and decryption failure probability; secret-key encryption parameters are not automatically suitable. The implementation checks dimensions and modulus identity only. This is a CPA encryption primitive without a KEM or CCA transform; ephemeral coefficients affect branching, so it is not constant-time.

## Independent batches and packed messages

Independent batches contain `count` consecutive `[a,b]` samples of length `n+1`; the count is not limited by `n`. Borrow individual ciphertexts with `LweIter` / `LweIterMut`. These iterators omit incomplete tails, while LWE batch entry points reject them.

- `encrypt_message_batch_to` requires exactly `messages.len()*(n+1)` output elements; `decrypt_message_batch_to` writes one message per ciphertext.
- Encoded and phase operations use `encrypt_encoded_batch[_to]` and `decrypt_phase_batch[_to]`. Secret-key batches require an owned `LweSecretKey<T>`; Signed views support single-ciphertext raw operations only. Encoded secret-key batches take `&LweEncryptionParameters`, as single-ciphertext encryption does; the key must match its nonzero dimension and modulus.
- Empty independent batches consume no randomness. RNG ordering need not match individual encryptions, and fixed seeds do not guarantee identical ciphertext bytes across versions.
- Batch entry points check complete lengths first; invalid messages or a panicking RNG can leave partial output and consume randomness.

Packed encryption stores one length-`n` shared mask and `count <= n` bodies, totaling `n+count` coefficients. Body `i` uses the mask rotated right by `i`, with its first `i` entries negated; these are not independent masks. Use `encrypt_message_packed` / `decrypt_message_packed` or `MultiMsgLwe::extract_lwe_at`, rather than `LweIter` over this storage. Encoded and phase operations use `encrypt_encoded_packed` and `decrypt_phase_packed`; pass a zero-filled encoded slice to encrypt zeros. An empty packed message list still samples and retains the shared mask.

## Key switching

Prepare `LweKeySwitchingParameters::try_new(output, basis)` from owned `LweEncryptionParameters` and an `ApproxSignedBasis` at the same modulus. Its noise sampler encrypts the key entries and may differ from fresh-message encryption noise. Pass `&parameters` with the Encoded/Signed input-key view and owned output key to `LweKeySwitchingKey::generate`. The key contains `input_dimension * levels * (output_dimension+1)` coefficients.

`key_switch[_to]` handles one ciphertext; `key_switch_batch[_to]` handles independent batches. Input and output may differ in dimension but must use the same ciphertext modulus and message encoding. Key switching does not switch moduli or re-encode, and the noise budget must include decomposition error and key-entry noise. Batch results match individual switches coefficient for coefficient; `_to` reuses output without heap scratch.

## Features and benchmarks

Default features are empty; `simd` enables the underlying crates' nightly SIMD arithmetic. Public contracts are documented in the [API sources](src/lib.rs).

The three benchmarks measure secret-key encryption/phase extraction (including output reuse and packed messages), public-key generation/encryption, and key-switch generation/evaluation. Run from the workspace root:

```sh
cargo bench -p primus_lwe --bench secret_key
cargo bench -p primus_lwe --bench public_key
cargo bench -p primus_lwe --bench key_switch
```
