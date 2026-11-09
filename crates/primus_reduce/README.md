# primus_reduce

English | [简体中文](README.zh_CN.md)

`primus_reduce` defines the modular-arithmetic contracts shared by modulus implementations and higher-level algorithms in Primus FHE.

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

## Overview

The traits in this crate put the modulus or reduction context in the receiver position:

```text
modulus.reduce_add(a, b)
modulus.reduce_mul_slice_to(a, b, output)
```

Operations are split into fine-grained traits so a modulus type implements only the scalar, slice, lazy, inverse, or fused operations it actually supports. Concrete modulus types and their ring-arithmetic kernels live in [`primus_modulus`](../primus_modulus). This crate also provides the modulus-independent `ModulusSwitch<T>` executor.

The main API groups are:

- scalar `Reduce*` traits for canonical arithmetic, inversion, division, and exponentiation;
- `Reduce*Slice` traits for bulk operations and SIMD dispatch;
- `LazyReduce*` traits whose results lie in `[0, 2 * modulus)`;
- `Modulus` and `ExplicitModulus` for modulus metadata;
- `RingContext` and `FieldContext` capability markers.

## Example

```rust
use primus_modulus::BarrettModulus;
use primus_reduce::prelude::*;

let modulus = BarrettModulus::new(97u64);

assert_eq!(modulus.reduce_add(80, 30), 13);
assert_eq!(modulus.reduce_mul(12, 9), 11);

let mut values = [80, 30];
let rhs = [30, 80];
modulus.reduce_add_slice_assign(&mut values, &rhs);
assert_eq!(values, [13, 13]);
```

## Caller contracts

This crate defines interfaces, not validation boundaries. Each public method documents its input range, representation, output state, and length requirements.

- Low-level numerical kernels may diagnose shape mismatches only with `debug_assert*!`; release callers must uphold the documented contracts.
- Dot products explicitly check equal slice lengths in every build profile. Canonical operands are always supported; wider input ranges are implementation-specific. Runtime and derived Barrett also accept operands below `2^(T::BITS - 2)`, independently of the destination modulus.
- Lazy results require a final once-reduction before they are treated as canonical residues.
- Fallible inverse traits report `ReduceError`; infallible inverse and division traits may panic when the required inverse does not exist.

`FieldContext` means that a modulus type implements the listed operation set. It does not prove that the modulus is prime or that every nonzero residue is invertible. Callers remain responsible for validating the algebraic assumptions required by their algorithms.

## Signed coefficients

`EncodeSigned<T>` converts bounded signed coefficients to canonical residues, without plaintext scaling or general modular reduction. It is exported from the crate root and `prelude`; custom modulus types can implement it without `Reduce` or `ReduceNeg`. Slice conversion requires equal input and output lengths.

`ReduceDotProductSigned<T>` computes the dot product of canonical residues and bounded signed coefficients without an encoded copy. It checks equal slice lengths and returns a canonical residue, or zero for empty inputs. Its signed input bounds match `EncodeSigned`; see the [modulus types](../primus_modulus/README.md#arithmetic-contracts) for support.

`RingContext<T>` includes both signed operation traits; `FieldContext<T>` inherits them through `RingContext<T>`. Both contexts require `T: FheUint`. Code needing only one operation can use its individual trait without the full context.

```rust
use primus_modulus::{NativeModulus, UintModulus};
use primus_reduce::prelude::*;

assert_eq!(UintModulus::new(97u64).encode_signed(-1), 96);
assert_eq!(NativeModulus::<u64>::new().encode_signed(-1), u64::MAX);
let mut output = [0u64; 3];
UintModulus::new(97).encode_signed_slice_to(&[-1, 0, 1], &mut output);
assert_eq!(output, [96, 0, 1]);
```

For an explicit modulus `q`, every coefficient must satisfy `value.unsigned_abs() < q`; this precondition is not checked in release builds. Every signed value, including the signed minimum, is representable under the native modulus. Imported coefficients must fit the destination modulus, even if they were valid under another modulus.

## Prepared modulus switching

`PrepareModulusSwitch` and `ModulusSwitch<T>` are exported from this crate. `source.prepare_switch_to(target)` returns the concrete executor, whose inherent `switch` and `switch_map` methods require no execution trait. `ModulusSwitch::new(source, target)` also accepts any pair of `Modulus` implementations.

Canonical source residues map to `round(value * target / source) mod target`, with ties upward and endpoint wrapping to zero. Either modulus may be native; explicit moduli must be at least two. This is integer ratio rounding, independent of modular division.

`RingContext` includes preparation, and `FieldContext` inherits it. Callers needing fewer capabilities can use `PrepareModulusSwitch` alone. Concrete implementations and a minimal example are in [`primus_modulus`](../primus_modulus/README.md#prepared-modulus-switching); raw reciprocal construction has additional [correctness preconditions](src/modulus_switch.rs).

`switch_map` carries a payload beside each coefficient for output conversion or accumulation without an intermediate buffer. If the iterator or callback panics, earlier effects remain.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
