# primus_encoding

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Plaintext coefficient encoding, decoding and integer slot packing for Primus FHE.

## APIs

| Codec | Encoding | Current use |
| --- | --- | --- |
| `RoundedCodec<T,M>` | `round(lift(m)*q/t) mod q` | LWE and TFHE lookup tables |
| `ScaledCodec<T,M>` | `lift(m)*round(q/t) mod q` | Single-modulus GLWE/NTRU |
| `BfvRnsCodec<T,M>` | `lift(m)*floor(Q/t) mod Q` | RNS coefficient scaling (`rns` feature) |
| `BatchingEncoder` | Two-row evaluations at `w^(±5^j)` | Shared BFV/BGV integer slots (`batching` feature, `u64`) |

Single-modulus constructors use `new(plaintext_modulus, ciphertext_modulus)`, for example `RoundedCodec::new(256u64, NativeModulus::new())` or `RoundedCodec::new(7u64, BarrettModulus::new(131))`. Construct once and reuse the codec. When `t` divides `q`, both encodings use the exact scale `q/t`; otherwise Rounded rounds each message while Scaled uses one integer scale.

The output `RoundedCodec` for ordinary TFHE LUTs uses the accumulator modulus and may choose a different plaintext modulus from the input. Decode with the same output plaintext modulus at the returned ciphertext modulus, especially for NTRU Q→q. See the [output encoding guide](../primus_tfhe/README.md#choosing-the-output-encoding).

The first three types encode coefficients. `BatchingEncoder` converts between plaintext slots and coefficients before a scheme applies its own message lifting. CKKS canonical embedding is not implemented.

## Encoding contracts

Messages and decoded outputs are canonical values of type `T` in `[0,t)`. Unsigned embedding lifts to `[0,t)`, and centered embedding to `[-floor(t/2),ceil(t/2))`. The caller supplies canonical accumulators and decoding inputs under the codec's ciphertext modulus.

Rounded encoding resolves ties away from zero on the integer lift. Both single-modulus codecs decode by rounding the canonical phase times `t/q`, with ties upward, modulo `t`. Use `MessageDecoder::from(&codec)` when only decoding is needed. See the [decoder contract](src/decode.rs).

Both codecs require `t >= 2` and `q > t`. Scaled also checks noiseless recovery at its fixed scale. Use `try_new` to handle a rejected configuration and establish the full encryption and evaluation noise budget separately. Producers and consumers must agree on the codec, embedding and moduli. See the [Rounded](src/rounded.rs) and [Scaled](src/scaled.rs) recovery contracts.

## BFV RNS

With `rns`, prepare `BfvRnsCodec::try_new(t_modulus, base_q, gamma_modulus)` for coefficient scaling under the product `Q` of an ordered ciphertext basis. The constructor checks moduli and noiseless recovery. For a bound `E` covering the full phase error, call `validate_noise_bound(E, embedding)` when preparing parameters. See the [constructor](src/bfv_rns/mod.rs) and [recovery bounds](src/bfv_rns/decode.rs).

`encode_coeffs_to` writes a coefficient-domain `CrtPolynomial` in basis order. For decoding, inverse-transform NTT data first and provide canonical residues. `decode_coeffs_to` overwrites its input and requires `decode_scratch_len(output.len())` scratch elements. Custom modulus contexts must satisfy the [cross-modulus base-conversion contract](../primus_rns/README.md#base-conversion).

## Integer slots and subrings

With `batching`, prepare `BatchingEncoder::try_new(PolyLength::new(n), BarrettModulus::new(p))`. The caller supplies a prime `p` with `p = 1 mod 2n` and `p < 2^62`. Inputs are canonical residues in `[0,p)`. `encode` accepts a slot prefix and zero-pads the rest; `decode` returns all `n` ordered slots. Use `encode_to` and `decode_to` to reuse buffers. See the [slot layout and plaintext automorphisms](src/batching.rs).

For a power-of-two ciphertext ring length `N >= n`, `embed_to` writes `f(X^(N/n))`. After decryption and coefficient decoding, `extract_to` checks and reverses the embedding. The plaintext transform still uses length `n`, and the ciphertext and secret stay at length `N`. See the [BFV subring example](../primus_bfv/examples/subring_slots.rs).

## Phase error diagnostics

Use `phase_error_magnitude` or `phase_error_magnitude_slice_to` on canonical coefficient phases. Encode the **expected message** using the codec, embedding and modulus of the extracted phase. Re-encoding the decoded value can hide a wrong result. The distance is unsigned and circular. In RNS, per-limb distances measure errors under the individual moduli. See the [runnable example and exact contract](src/phase_error.rs).

## Further reading

The [public API sources](src/lib.rs) document method contracts. Commands and measured workloads are recorded in the [single-modulus benchmark](benches/plaintext_codec.rs) and [RNS benchmark](benches/bfv_rns.rs); see the [testing guide](../../guides/development/testing.md) for validation entry points.

## Features

- Default: single-modulus codecs and phase error diagnostics.
- `rns`: enables BFV RNS coefficient encoding and decoding.
- `batching`: enables fixed-`u64` integer slots and plaintext subring embedding, independently of `rns`.
- `simd`: enables nightly SIMD arithmetic; does not enable `rns` or `batching` by itself.
