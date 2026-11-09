# primus_ntt

English | [简体中文](README.zh_CN.md)

`primus_ntt` provides in-place negacyclic number-theoretic transforms for polynomials in `Z_q[X] / (X^N + 1)`. It includes generic unsigned-integer tables, optimized `u32` and `u64` tables, direct monomial transforms, and modulus-major DCRT transforms for [Primus FHE](../../README.md).

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, NTT representation, numerical contracts, and backend selection are unstable and may change incompatibly at any time.

## Core types

| Type | Role |
| --- | --- |
| `NttTable` | Common construction and forward/inverse transform contract |
| `MonomialNttTable` | Directly transforms `coeff * X^degree` without building a coefficient polynomial |
| `UintNttTable<T>` | Generic unsigned-integer implementation using Shoup multiplication |
| `U32NttTable` | Optimized table for `u32` moduli below `2^30` |
| `U64NttTable` | Optimized table for `u64` moduli below `2^62` |
| `DcrtTable<Ntt>` | One same-length NTT table per CRT modulus |
| `U32DcrtTable`, `U64DcrtTable`, `UintDcrtTable<T>` | Common DCRT aliases |

Transforms run in place without per-call scratch allocation. Construct and reuse a table for each ring and modulus.

## Example

```rust
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_shape::PolyLength;

let modulus = BarrettModulus::new(193_u32);
let table = U32NttTable::new(PolyLength::new(32), modulus).unwrap(); // N = 32; 2N divides 193 - 1
let expected: Vec<u32> = (0..table.poly_length().get()).map(|i| i as u32).collect();
let mut values = expected.clone();

table.transform_slice(&mut values);
// `values` now holds NTT evaluations in bit-reversed order.
table.inverse_transform_slice(&mut values);

assert_eq!(values, expected);
```

Tables are immutable and implement `Send + Sync`, so they can be shared across threads operating on separate buffers. Cloning `U32NttTable` or `U64NttTable` copies precomputed storage; prefer sharing the table in repeated paths.

`NttAutomorphismPermutation::new(degree, poly_length)` prepares `X -> X^degree` in bit-reversed order for odd `degree` in `[1, 2N)`. `apply_to` takes exactly `N` input and output evaluations and preserves their residue range. The map also applies independently to each DCRT component; homomorphic use still requires a scheme-specific key switch. See the [automorphism API](src/automorphism.rs).

## Representation and ranges

For `N = 2^log_n`, the forward transform consumes coefficients in ascending-power order and produces evaluations in bit-reversed order. The inverse transform consumes that bit-reversed representation and restores ascending-power coefficient order, including inverse-length normalization.

Every single-modulus input or output slice must contain exactly `table.poly_length().get()` values; a mismatched length panics. Values from different tables are interchangeable only when their roots, ordering and normalization agree, not merely their lengths and moduli.

| Operation | Input range | Output range |
| --- | --- | --- |
| `transform_slice` | `[0, q)` | `[0, q)` |
| `inverse_transform_slice` | `[0, q)` | `[0, q)` |
| `lazy_transform_slice` | `[0, 4q)` | `[0, 4q)` |
| `lazy_inverse_transform_slice` | `[0, 2q)` | `[0, 2q)` |

Lazy values represent residues modulo `q`, but their wider integer ranges are part of the calling contract. In particular, a lazy forward result is not automatically a valid lazy-inverse input; normalize it to the inverse method's accepted range first.

Transforms operate on mutable slices. When using [`primus_poly`](../primus_poly/README.md) wrappers, borrow their storage for the transform and wrap that same storage in the resulting representation.

## Construction constraints

- Constructors take [`primus_shape::PolyLength`](../primus_shape/README.md#polynomial-length); `poly_length()` returns the same type.
- The modulus must be prime and admit a primitive `2N`-th root, requiring `2N` to divide `q - 1`. Primality is a caller precondition; neither construction nor `FieldContext` proves it.
- `UintNttTable<T>` requires `1 < q < 2^(T::BITS - 2)`; `U32NttTable` requires `q < 2^30`, and `U64NttTable` requires `q < 2^62`. The two spare bits make lazy values below `4q` representable.
- The generic table also requires the root order `2N` to fit `T` and `N < q`.

`NttTable::new` searches for a primitive root and prepares a reusable table. Construction errors and exact conditions are documented in the [NTT API](src/ntt/mod.rs).

## Monomial transforms

`MonomialNttTable` writes the NTT representation of `coeff * X^degree` directly into an exact-length output slice. The degree is interpreted modulo `2N`, matching `X^N = -1` in the negacyclic ring.

`transform_monomial` requires `coeff` to be canonical, meaning `0 <= coeff < q`; it does not reduce or validate the coefficient. Use `transform_coeff_one_monomial` and `transform_coeff_minus_one_monomial` for the common `X^degree` and `-X^degree` cases.

Custom `MonomialNttTable` implementations must supply the documented root values and ordering. The default monomial methods check the exact length of the root array they use before writing output; direct fills do not read root arrays. Root values and ordering are not validated. See the [monomial API](src/ntt/mod.rs) for the complete contract.

## DCRT layout

`DcrtTable` requires a nonempty modulus list and one common `PolyLength`. `poly_length()` returns the ring length; `rns_poly_len()` returns the total `moduli_count * N` elements, which must fit `usize`. Coefficient and transform slices use the table's modulus order in modulus-major layout:

```text
[a_0 mod q_0, ..., a_(N-1) mod q_0,
 a_0 mod q_1, ..., a_(N-1) mod q_1,
 ...]
```

This matches `CrtPolynomial` and `DcrtPolynomial` in [`primus_poly`](../primus_poly/README.md). DCRT callers must maintain the exact total length, modulus order, coefficient ranges and component transform conventions; total-length checks are debug diagnostics only. See the [DCRT API](src/dcrt/mod.rs).

`DcrtTable` provides full-polynomial forward/inverse transforms and `transform_coeff_one_monomial` for all limbs. Use `iter()` or `ntt_tables()` to access component tables for their lazy and general monomial operations.

## SIMD backends and build target

Default features are empty. Specialized x86-64 tables select available scalar or SIMD kernels at runtime; these kernels do not require the optional `simd` feature. Other architectures use scalar implementations. The `simd` feature enables portable-SIMD support in dependencies and requires nightly Rust.

The repository [build configuration](../../.cargo/config.toml) uses `target-cpu=native`. Override its rustflags when producing portable binaries; runtime dispatch alone does not make a host-targeted build portable.

## Testing and benchmarks

```text
cargo test -p primus_ntt
cargo bench -p primus_ntt --bench bench_ntt
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
