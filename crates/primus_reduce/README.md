# primus_reduce

English | [简体中文](README.zh_CN.md)

`primus_reduce` defines the modular-arithmetic contracts shared by modulus implementations and higher-level algorithms in Primus FHE.

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

## Overview

Use the operation traits from the [prelude](src/prelude.rs) with concrete
moduli from [`primus_modulus`](../primus_modulus/README.md). The traits cover
canonical, lazy, slice, signed, and fused arithmetic. `RingContext` and
`FieldContext` describe supported operations. Algorithms requiring a prime
modulus or invertible elements must establish those conditions separately.

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

Use canonical residues and complete buffers unless the operation documents a
different range. Apply once-reduction before using lazy outputs as canonical
residues. See the [scalar](src/ops.rs) and [slice](src/slice_ops.rs) traits for
input ranges, length checks, and fallible inverse operations.

## Signed coefficients

[`EncodeSigned<T>`](src/signed.rs) lifts a signed coefficient to a canonical
residue without plaintext scaling. An explicit modulus `q` requires magnitude
strictly below `q`. The native modulus represents every signed value.
`ReduceDotProductSigned<T>` uses the same signed input contract and works
without an encoded copy.

```rust
use primus_modulus::{NativeModulus, UintModulus};
use primus_reduce::prelude::*;

assert_eq!(UintModulus::new(97u64).encode_signed(-1), 96);
assert_eq!(NativeModulus::<u64>::new().encode_signed(-1), u64::MAX);
let mut output = [0u64; 3];
UintModulus::new(97).encode_signed_slice_to(&[-1, 0, 1], &mut output);
assert_eq!(output, [96, 0, 1]);
```

## Prepared modulus switching

Use [`PrepareModulusSwitch` or `ModulusSwitch::new`](src/modulus_switch.rs) to
prepare one source/target pair. Given a canonical source residue, `switch`
rounds `value * target / source` to nearest with ties upward, then wraps the
target endpoint to zero. Each modulus is at least two and may be native.
`switch_map` carries a payload alongside each residue to avoid an intermediate
buffer. Callback effects already performed remain if a batch panics.
See the [example in primus_modulus](../primus_modulus/README.md#prepared-modulus-switching).

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
