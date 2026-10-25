# primus_factor

English | [简体中文](README.zh_CN.md)

`primus_factor` provides precomputed factors for repeated multiplication by a fixed value under a fixed modulus. The precomputation replaces division in scalar, slice, and optional SIMD multiplication paths.

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

## Factor types

| Type | Precomputation | Intended use |
| --- | --- | --- |
| `ShoupFactor<T>` | `value` and `floor(value * 2^T::BITS / modulus)` | General scalar and slice multiplication by a fixed value |
| `MultiplyFactor` | `u64` operand and `floor((operand << bit_shift) / modulus)` | Specialized `u64` kernels with an explicit 32-, 52-, or 64-bit shift |
| `SimdShoupFactor<T>` | One Shoup value and quotient per SIMD lane | Explicit lane-wise SIMD multiplication when the `simd` feature is enabled |

`ShoupFactor` is the normal choice. It implements scalar multiplication, in-place and out-of-place slice multiplication, and fused slice operations. `MultiplyFactor` is a lower-level building block for kernels whose shift is already part of their numerical contract.

## Example

```rust
use primus_factor::{FactorMul, FactorSliceOps, LazyFactorMul, ShoupFactor};

let modulus = 97u64;
let factor = ShoupFactor::new(12, modulus);

assert_eq!(factor.factor_mul_modulo(9, modulus), 11);

let lazy = factor.lazy_factor_mul_modulo(9, modulus);
assert!(lazy < 2 * modulus);
assert_eq!(lazy % modulus, 11);

let mut values = [9, 10, 11];
factor.factor_mul_slice_assign(&mut values, modulus);
assert_eq!(values, [11, 23, 35]);
```

Use `FactorMul` / `LazyFactorMul` for scalar operations and `FactorSliceOps` / `LazyFactorSliceOps` for slices. `FactorBase` provides construction; `Factor` combines the complete operation set.

## Caller contracts

Factors deliberately do not store their modulus. The caller must pass the same modulus used to construct or reset a factor to every later operation.

- `ShoupFactor<T>` requires `value < modulus` and `modulus < 2^(T::BITS - 1)`.
- `MultiplyFactor` requires canonical operands, `bit_shift` equal to 32, 52, or 64, and `modulus < 2^(bit_shift - 2)`. The const `BIT_SHIFT` used by multiplication must equal the runtime `bit_shift` used during construction.
- Lazy operations return a representative in `[0, 2 * modulus)`; canonical operations return a value in `[0, modulus)`.
- Slice inputs and accumulators are canonical. Out-of-place and fused operations require their slices to have equal lengths.
- Raw constructors require the value, quotient, and later modulus to agree exactly.

Some low-level contracts are diagnosed only by `debug_assert*!`. Release callers must validate them at an appropriate boundary before entering repeated arithmetic kernels.

## SIMD feature

The optional `simd` feature requires nightly and is disabled by default. It enables portable-SIMD support, including `SimdShoupFactor` and `SimdFactorMul` for explicit factor broadcasting or per-lane packing.

Stable builds can also accelerate supported `u64` slices on x86-64 CPUs; disabling `simd` does not imply scalar-only execution. Arithmetic contracts are unchanged. See the [benchmark guide](benches/README.md) to compare scalar and precomputed-factor workloads.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
