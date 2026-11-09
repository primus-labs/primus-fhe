# primus_encoding

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Plaintext coefficient encoding and decoding for Primus FHE.

## APIs

| Codec | Encoding | Current use |
| --- | --- | --- |
| `RoundedCodec<T,M>` | `round(lift(m)*q/t) mod q` | LWE and TFHE lookup tables |
| `ScaledCodec<T,M>` | `lift(m)*round(q/t) mod q` | Single-modulus GLWE/NTRU |
| `BfvRnsCodec<T,M>` | `lift(m)*floor(Q/t) mod Q` | RNS coefficient scaling (`rns` feature) |

Single-modulus constructors use `new(plaintext_modulus, ciphertext_modulus)`, for example `RoundedCodec::new(256u64, NativeModulus::new())` or `RoundedCodec::new(7u64, BarrettModulus::new(131))`. Construct once and reuse the codec. When `t` divides `q`, both encodings use the exact scale `q/t`; otherwise Rounded rounds each message while Scaled uses one integer scale.

The output `RoundedCodec` for ordinary TFHE LUTs uses the accumulator modulus and may choose a different plaintext modulus from the input. Decode with the same output plaintext modulus at the returned ciphertext modulus, especially for NTRU Q→q. See the [output encoding guide](../primus_tfhe/README.md#choosing-the-output-encoding).

These are coefficient codecs. BFV/BGV integer slot packing, BGV's unscaled plaintext lifting, and CKKS canonical embedding are not implemented.

## Encoding contracts

Messages and decoded outputs use the coefficient type `T`, with canonical values in `[0,t)`. Unsigned embedding lifts messages to `[0,t)`; centered embedding lifts them to `[-floor(t/2),ceil(t/2))`, including `1 -> -1` when `t=2`. Accumulators and decoding inputs must be canonical ciphertext residues under the codec's modulus. These ciphertext input ranges are caller preconditions, not validated by the codecs.

Rounded encoding rounds ties away from zero on the integer lift. Both single-modulus codecs decode by rounding the canonical phase times `t/q`, with ties upward, modulo `t`. Only when `t` divides `q` can this be written as `round(c/delta) mod t` with `delta=q/t`; a power-of-two rounded scale alone is insufficient.

`RoundedCodec` requires `t >= 2` and `q > t`. `ScaledCodec` additionally checks `abs(t*delta-q)*(t-1) < q/2`, where `delta=round(q/t)` with ties upward. This is sufficient for noiseless recovery under either embedding and guarantees `(t-1)*delta < q`. For an integer lift `m` and phase noise `e`, a sufficient Scaled recovery condition is `abs((t*delta-q)*m + t*e) < q/2`.

`RoundedCodec::try_new` and `ScaledCodec::try_new` return `CodecError` on invalid domains or a failed fixed-scale recovery bound; `new` panics on the same errors. These checks do not establish an encryption or evaluation noise budget. Producers and consumers must agree on the codec, embedding and moduli.

Use `MessageDecoder::from(&codec)` when only decoding is needed. Single-modulus slice methods use `_to` for separate output and `_assign` for in-place updates. Batch encoding validates message ranges and exact lengths before writing; methods that add encoded messages retain the existing accumulator contents.

## BFV RNS

With the `rns` feature, `BfvRnsCodec::try_new(plaintext_modulus, base_q, gamma_modulus)` prepares coefficient scaling under the product `Q` of an ordered ciphertext basis. It returns `BfvRnsCodecError<T>` on invalid modulus or recovery conditions; `new` panics on the same errors. The constructor checks the [modulus ranges and coprimality conditions](src/bfv_rns/mod.rs), as well as `Q > 4*(Q % t)*(t-1)` and `gamma > 4*k`, where `k` is the number of ciphertext moduli. These conservative bounds ensure noiseless recovery, not an encryption noise or security budget.

For phase `delta*m+e`, with `delta=floor(Q/t)`, a sufficient decode condition is `abs(t*e-(Q % t)*m)/Q + k/gamma < 1/2`.

For a complete phase-noise magnitude bound `E`, call `validate_noise_bound(E, embedding)` when preparing parameters. It checks `(t*E + (Q % t)*A)/Q + k/gamma < 1/2`, with `A=t-1` for unsigned lifting and `A=floor(t/2)` for centered lifting. Failure returns `InsufficientNoiseRecovery`; this sufficient bound can reject cases that would still decode. Include all encryption and evaluation contributions in `E`.

`encode_coeffs_to` produces coefficient-domain `CrtPolynomial` data in the basis order; `add_encode_coeffs_assign` adds to an existing canonical accumulator. Polynomial length comes from the plaintext slice. `decode_coeffs_to` overwrites its coefficient-domain input and needs exactly `decode_scratch_len(output.len())` scratch elements: zero for a single-modulus basis, one RNS polynomial otherwise. Perform inverse NTT before decoding transformed data.

Each input residue must be canonical under its basis modulus. Custom modulus contexts must also satisfy the [cross-modulus base-conversion contract](../primus_rns/README.md#base-conversion) inherited by the codec; the supplied Barrett contexts meet it. This codec is a BFV building block, not a complete BFV scheme.

## Phase error diagnostics

`phase_error_magnitude(phase, expected_phase, modulus)` returns the exact
nonnegative circular distance in the coefficient type, in `[0, floor(q/2)]`.
It handles Native's `2^BITS` modulus without floating-point conversion.
`phase_error_magnitude_slice_to` writes these distances into a supplied slice;
all three lengths must match, including for empty inputs. Length mismatches
panic before any output is written. Canonical residues are caller preconditions.

Extract the coefficient phase with the encryption library, then encode the
**expected message** using the same codec, embedding and modulus as that phase.
For example:

```rust
use primus_encoding::{PlaintextEmbedding, RoundedCodec, phase_error_magnitude};
use primus_modulus::PowOf2Modulus;

let modulus = PowOf2Modulus::new(256u64);
let codec = RoundedCodec::new(4, modulus);
let expected_phase = codec.encode_value(0, PlaintextEmbedding::Unsigned);
let phase = 64; // The expected message was 0, but this phase decodes to 1.
assert_eq!(phase_error_magnitude(phase, expected_phase, modulus), 64);
```

Re-encoding the decoded value would give a zero residual in this example and
hide the incorrect message. Decode correctness remains a separate check. The
distance has no sign, cannot recover an integer error after modular wraparound,
and includes any transform or evaluation error already present in the phase.
Per-limb RNS distances do not measure the error under the product modulus.

## Further reading

The [public API sources](src/lib.rs) document method contracts. Commands and measured workloads are recorded in the [single-modulus benchmark](benches/plaintext_codec.rs) and [RNS benchmark](benches/bfv_rns.rs); see the [testing guide](../../guides/development/testing.md) for validation entry points.

## Features

- Default: single-modulus codecs and phase error diagnostics.
- `rns`: enables BFV RNS coefficient encoding and decoding.
- `simd`: enables nightly SIMD arithmetic; does not enable `rns` by itself.
