# primus_integer

English | [简体中文](README.zh_CN.md)

`primus_integer` defines the integer traits and fixed-width multi-limb arithmetic used by the Primus FHE workspace.

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

## Overview

The main APIs are:

- `Integer`, which collects the common arithmetic, bit, and conversion capabilities required by generic kernels;
- `SignedInteger` and `UnsignedInteger`, which add sign-specific operations and width-matched companion types;
- fine-grained traits for checked, overflowing, wrapping, carrying, widening, and division operations;
- `BigUint<S>`, a fixed-width unsigned integer over borrowed or owned little-endian limb storage;
- optional default-width portable SIMD abstractions.

## Example

```rust
use primus_integer::{BigUint, UnsignedInteger};

fn significant_bits<T: UnsignedInteger>(value: T) -> u32 {
    value.bit_width()
}

assert_eq!(significant_bits(0x100u64), 9);

let value = BigUint(vec![u64::MAX, 1]);
assert_eq!(value.len(), 2);
assert_eq!(value.bit_width(), 65);
```

## `BigUint` representation and caller contracts

`BigUint<S>` is a low-level, fixed-width integer representation for FHE, RNS, and decomposition algorithms. It is not a general-purpose, automatically growing big-integer type or an input-validation boundary.

The limbs are stored in little-endian order. The limb count and leading zero limbs are part of the representation and equality: for example, `BigUint([1u64])` and `BigUint([1u64, 0])` are different representations.

Effective bit widths use `u32`; limb counts and storage lengths use `usize`. `checked_bit_width()` ignores leading zero limbs and returns `Some(0)` for empty or zero values, or `None` when the width exceeds `u32::MAX`. `bit_width()` returns the same width and panics on overflow.

Callers must maintain the following contracts:

- every input, output, accumulator, and modulus participating in one operation has the same limb count;
- operations that access the least-significant limb receive nonempty storage;
- the `bits` argument to `left_shift_assign` and `right_shift_assign` is less than `T::BITS`; these methods perform an intra-limb shift, not an arbitrary whole-integer shift;
- operands passed to modular operations are already reduced to `[0, modulus)`.

These preconditions are not guaranteed to be checked in release builds. See the [public API](src/lib.rs) for each method's complete contract.

Arithmetic remains fixed-width: methods report carry, borrow, or a high limb where documented, and shifts return or discard shifted-out bits according to their individual contracts. They do not resize the representation.

`BigUint` operations are not implemented as constant-time operations and must not be assumed to provide side-channel resistance.

## Serde feature

The default feature set is empty. Enable `primus_integer/serde` to serialize and deserialize `BigUint<S>` when `S` supports the corresponding serde trait. Arithmetic traits, including `Integer`, do not require serde, even when the feature is enabled. Generic serialization code must state its own serde bounds.

Serialization preserves the complete stored limb sequence, including leading zeros. Deserialization restores raw storage; it does not validate a limb count, modulus, or arithmetic domain. This is not a versioned format for keys or parameters.

## SIMD feature

The `simd` feature enables the `SimdInteger`, `SimdArray`, and related traits. It uses Rust's unstable `portable_simd` API and therefore requires nightly.

The default vector types are selected from the target CPU features. `VECTOR_BITS` uses `u32`; `LANE_COUNT` uses `usize` for array lengths. Generic code should use the associated `SimdT`, `MaskT`, and `Array` types instead of spelling a lane count directly.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
