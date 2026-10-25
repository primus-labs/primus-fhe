# primus_poly

English | [简体中文](README.zh_CN.md)

`primus_poly` provides storage wrappers and arithmetic operations for the polynomial representations used throughout [Primus FHE](../../README.md). The wrappers separate coefficient, NTT, CRT/DCRT, multi-limb, and Fourier data so callers can make each representation explicit without storing per-polynomial context.

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, data representations, and numerical contracts are unstable and may change incompatibly at any time.

## Representations

| Type | Representation and layout | Main operations |
| --- | --- | --- |
| `Polynomial<S>` | `N` coefficients in ascending-power order under one modulus | Add, subtract, negate, scalar/factor multiplication, negacyclic monomials, naive multiplication, evaluation, and sampling |
| `NttPolynomial<S>` | `N` point values under one modulus; ordering is defined by the NTT context | Point-wise arithmetic, fused multiply-add, and inverse |
| `CrtPolynomial<S>` | Modulus-major coefficient data: one contiguous `N`-coefficient polynomial per modulus | Component-wise arithmetic, scalar/factor operations, and negacyclic monomials |
| `DcrtPolynomial<S>` | Modulus-major NTT data: one contiguous `N`-value transform per modulus | Point-wise arithmetic, fused multiply-add, inverse, and factor butterfly kernels |
| `BigUintPolynomial<S>` | Coefficient-major data: each coefficient is a fixed-width little-endian limb chunk | Multi-limb modular add, subtract, and negate |
| `FourierPolynomial<S>` | Independent complex evaluations; ordering is defined by the Fourier backend | Point-wise add, subtract, negate, multiply, fused multiply-add, and scalar multiplication |

`primus_poly` stores values and implements arithmetic; it does not own transform tables or perform representation selection. [`primus_ntt`](../primus_ntt) converts between coefficient and NTT/CRT and DCRT representations, while [`primus_fft`](../primus_fft) supplies Fourier transforms.

For flat scalar buffers, use slices and the `Reduce*Slice` traits from
[`primus_reduce`](../primus_reduce/README.md), such as
`modulus.reduce_add_slice_assign(lhs, rhs)`. Polynomial and ciphertext wrappers
retain their representation-specific operations. DCRT inverse butterflies remain
available through `DcrtPolynomial::butterfly_mul_factor_to`.

## Example

```rust
use primus_modulus::CompactModulus;
use primus_poly::PolynomialOwned;

let modulus = CompactModulus::new(97_u64);
let mut lhs = PolynomialOwned::from_slice(&[80, 12, 5, 40]);
let rhs = PolynomialOwned::from_slice(&[30, 9, 96, 70]);

lhs.add_assign(&rhs, modulus);
assert_eq!(lhs.as_slice(), &[13, 21, 4, 13]);

// Multiplication by X in Z_97[X]/(X^4 + 1).
lhs.mul_monomial_assign(1, modulus);
assert_eq!(lhs.as_slice(), &[84, 13, 21, 4]);
```

## Ring polynomial length

FHE layouts and transform tables use [`primus_shape::PolyLength`](../primus_shape/README.md#polynomial-length), a checked coefficient count `N`. Raw polynomial wrappers store no separate ring length, so their element counts remain `usize`.

The raw wrappers use `len()` / `is_empty()` to inspect their complete storage:

| Wrapper | What `len()` counts | One complete polynomial |
| --- | --- | --- |
| `Polynomial` | Coefficients | `N` |
| `NttPolynomial` | NTT evaluations | `N` |
| `FourierPolynomial` | Complex values | `N/2` |
| `CrtPolynomial`, `DcrtPolynomial` | Residues across all moduli | `moduli_count * N` |

These accessors do not validate layout. Raw wrappers can represent empty, arbitrary-length or packed storage; an operation's contract determines which it accepts.

## Storage and ownership

Most polynomial types are generic over a backing store `S` implementing the contiguous-storage traits from [`primus_data`](../primus_data/README.md). Owned `Vec` aliases and borrowed slice aliases are available for the common coefficient, NTT, and Fourier forms. CRT, DCRT, and multi-limb wrappers can likewise be constructed over owned or borrowed storage through their generic types.

`as_view()` and `as_mut_view()` borrow the complete storage while preserving the polynomial representation. Equivalent `From<&Wrapper<S>>` / `From<&mut Wrapper<S>>` conversions return slice-backed wrappers without copying. `into_inner()` consumes a wrapper and returns its original storage, including borrowed or aligned storage; it does not allocate or turn a borrow into an owner.

Operation names describe where results are written:

- `operation` consumes a mutable-capable wrapper, updates its storage, and returns the wrapper;
- `operation_assign` updates `self` in place;
- `operation_to` writes to a separate output wrapper;
- `operation_rev_assign` writes a reversed non-commutative operation into its mutable operand.

Consuming a wrapper backed by `&mut [T]` still updates the caller's slice.

## Layout and arithmetic contracts

The wrappers deliberately do not store polynomial length, modulus values, transform tables, normalization state, or limb width. Callers must establish these invariants at the owning FHE/RNS/transform boundary and preserve them across low-level operations:

- all operands and outputs participating in one operation have the same representation and layout;
- backing storage is exactly divisible by the supplied polynomial length or multi-limb coefficient width;
- CRT/DCRT storage has length `moduli.len() * poly_length`; component-wise scalar, factor, and modulus slices contain one entry per component, while per-point factor polynomials such as butterfly `w` have the same modulus-major layout and length as the backing storage;
- values satisfy the canonical or lazy range required by the selected `primus_reduce` or `primus_factor` operation;
- monomial exponents belong to the documented `[0, 2N)` range, and methods requiring a power-of-two `N` receive one;
- NTT and Fourier operands were produced for compatible transform contexts.

Raw wrappers do not validate these conditions; callers must uphold the selected operation's contract.

`add_mul_monomial_pair_assign` accumulates `first * X^r + second * X^s`; its free-function form accepts a flat batch of complete polynomials. Sources and accumulator must be canonical, with equally sized power-of-two polynomials and exponents in `[0, 2N)`.

The Barrett-domain `lazy_add_mul_monomial_pair_assign` and `lazy_add_mul_monomial_assign` instead accept an accumulator in `[0, 2q)` and retain that range; sources remain canonical. Normalize with `ReduceOnceSlice::reduce_once_slice_assign` before passing the result to ordinary NTT or another operation requiring canonical input. Exact batch and range contracts are in the [monomial APIs](src/monomial.rs) and [lazy APIs](src/monomial/lazy.rs).

`CoeffAutomorphismPermutation::new(d, poly_length)` prepares `X -> X^d` modulo `X^N + 1` for odd `d` in `[1, 2N)`. Reuse `apply_to` on canonical residues or `apply_signed_to` on signed coefficients whose required negations are representable. Both buffers contain exactly `N` coefficients. This permutation does not perform cryptographic key switching; the NTT counterpart lives in `primus_ntt`. See the [automorphism API](src/automorphism.rs).

## Random sampling

`Polynomial::random` collects uniform residues under a modulus;
`Polynomial::random_with_distribution` collects samples from a caller-selected
`rand::distr::Distribution`. Both support `FromIterator` storage and require an
RNG implementing `rand::Rng` and `rand::CryptoRng`. See the [sampling API](src/poly/random.rs).

For specialized sampling, filling existing buffers, or adding noise, use the
sampler's slice APIs from [`primus_distr`](../primus_distr/README.md), then wrap
that storage in the appropriate polynomial type. Sample non-uniform distributions
in the coefficient domain before transforming. CRT sampling must encode the
same logical coefficient sample under every component modulus; independently
sampling Gaussian noise in each modulus block would represent a different value.

## Monomial arithmetic benchmark

[monomial.rs](benches/monomial.rs) compares two single-term accumulations with one paired accumulation for `acc += first * X^r + second * X^s` modulo `X^N + 1`. Parameters are in the bench source. These are arithmetic measurements, not PBS/CBS timings.

```text
cargo bench -p primus_poly --bench monomial
```

## SIMD feature

The optional `simd` feature enables the portable-SIMD DCRT butterfly path and the matching SIMD support in arithmetic dependencies. It is disabled by default and requires a nightly Rust toolchain.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
