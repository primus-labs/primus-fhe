# primus_barrett_derive

English | [简体中文](README.zh_CN.md)

`primus_barrett_derive` implements the `Barrett` derive macro used by [`primus_modulus`](../primus_modulus/README.md) to create zero-sized modulus contexts for compile-time constants.

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its generated API and numerical contracts are unstable and may change incompatibly at any time.

Workspace crates should normally enable the `derive` feature of `primus_modulus` instead of depending on this procedural-macro crate directly:

```toml
[dependencies]
primus_modulus = { path = "../primus_modulus", features = ["derive"] }
```

Generated code uses absolute `::primus_modulus` paths. Keep that dependency name;
if Cargo renames it, provide a crate-root alias named `primus_modulus`. Depending
only on `primus_barrett_derive` does not provide the arithmetic implementation
referenced by the expansion.

## Example

```rust
use primus_modulus::{Barrett, reduce::prelude::*};

#[derive(Barrett)]
#[modulus(ty = u32, value = 536813569)]
struct Modulus;

assert_eq!(Modulus::value(), 536_813_569);
assert_eq!(Modulus.reduce_mul(12_345, 67_890), 301_288_481);
```

The visibility of the generated `value()` and `ratio()` functions follows the visibility of the unit struct.

## Input contract

The macro accepts only a unit struct with one `modulus` attribute:

```rust,ignore
#[derive(Barrett)]
#[modulus(ty = u64, value = 1125899906826241)]
pub struct CiphertextModulus;
```

- `ty` must be the bare identifier `u16`, `u32`, or `u64`.
- `value` must satisfy `1 < value < 2^(BITS - 2)` for that type.
- Invalid structures, types, literals, and modulus ranges produce compile-time errors.

## Generated API

The resulting unit struct needs no runtime context allocation and provides:
- associated `value()` and `ratio()` functions;
- `primus_reduce` scalar, slice, lazy-reduction, inverse, exponentiation, fused-operation, and dot-product implementations. Dot products share runtime Barrett's input bound: each operand is below `2^(BITS - 2)`, even when larger than the destination modulus;
- bounded signed coefficient conversion through `EncodeSigned`;
- `Copy`, `Clone`, `PartialEq`, `Eq`, `Debug`, and `Hash` implementations.

Do not derive those standard traits separately on the same struct, because the generated implementations would conflict.

## SIMD

Enable both `derive` and `simd` on `primus_modulus` for portable-SIMD support, which requires nightly. Stable builds can also use supported native kernels; see [modulus features](../primus_modulus/README.md#features).

Scalar and SIMD expansions share `BarrettModulus` contracts: callers preserve slice dimensions, lazy results lie in `[0, 2*modulus)`, and inversion requires an invertible input. A compile-time constant modulus is not necessarily prime.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
