# primus_modulus

English | [简体中文](README.zh_CN.md)

`primus_modulus` provides the concrete modulus contexts and arithmetic kernels that implement the contracts defined by [`primus_reduce`](../primus_reduce/README.md).

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

## Modulus types

| Type | Modulus | Intended use |
| --- | --- | --- |
| `NativeModulus<T>` | implicit `2^T::BITS` | wrapping arithmetic in the native word ring |
| `PowOf2Modulus<T>` | representable power of two greater than one | mask-based arithmetic for an explicit power-of-two modulus |
| `BarrettModulus<T>` | `1 < modulus < 2^(T::BITS - 2)` | repeated multiplication, wide reduction, fused slice operations, and dot products |
| `CompactModulus<T>` | `1 < modulus < 2^(T::BITS - 2)` | basic add, subtract, negate, and inverse operations without precomputed data |
| `UintModulus<T>` | any representable `modulus > 1` | basic arithmetic when the compact range restriction is unsuitable |

## Example

```rust
use primus_modulus::{BarrettModulus, reduce::prelude::*};

let modulus = BarrettModulus::new(97u64);

assert_eq!(modulus.reduce_add(80, 30), 13);
assert_eq!(modulus.reduce_mul(12, 9), 11);

let lhs = [12, 20, 31];
let rhs = [9, 10, 11];
let mut output = [0; 3];
modulus.reduce_mul_slice_to(&lhs, &rhs, &mut output);
assert_eq!(output, [11, 6, 50]);
```

## Choosing and constructing a modulus

Use the constructors on the types above, or describe Native, PowOf2, and
Barrett choices with [`ModulusConfig`](src/config.rs) and prepare them with
`M::try_from(config)`. For Barrett, `try_new` checks the range and
[`from_parts`](src/barrett/mod.rs) accepts a validated modulus and its matching
little-endian reciprocal. Preserve the documented ranges when constructing or
changing the public fields of Compact and Uint contexts.

## Prime preparation

Use [`is_prime_u64`](src/prime.rs) to test public u64 parameters for primality.
Check NTT compatibility and cryptographic parameters separately.

## Features

- `derive` re-exports the `Barrett` derive macro for compile-time constant moduli. See [`primus_barrett_derive`](../primus_barrett_derive/README.md).
- `simd` enables nightly portable-SIMD kernels and slice dispatch. When `derive` is also enabled, generated Barrett contexts use the corresponding SIMD paths.

Both features are disabled by default. The `simd` feature requires a nightly Rust toolchain.

Stable builds can also select supported x86_64 kernels; disabling `simd` does not imply scalar-only machine code. Scalar and accelerated paths have the same arithmetic contracts. Performance depends on the CPU and workload; see the [benchmark guide](benches/README.md).

## Arithmetic contracts

Use the [operation contracts](../primus_reduce/README.md#caller-contracts).
[`BarrettModulus`](src/barrett/mod.rs) documents its full-width scalar reduction
and dot products whose operands can exceed the destination modulus.
[`ReduceDotProductSigned`](../primus_reduce/src/signed.rs) is supported by Native,
PowOf2, Barrett, and derived Barrett.

## Prepared modulus switching

All five modulus types and derived Barrett contexts implement the shared
[modulus switching contract](../primus_reduce/README.md#prepared-modulus-switching).

```rust
use primus_modulus::{BarrettModulus, NativeModulus, reduce::PrepareModulusSwitch};

let conversion = BarrettModulus::new(97u32).prepare_switch_to(NativeModulus::new());
assert_eq!(conversion.switch(48), 2_125_344_641);
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
