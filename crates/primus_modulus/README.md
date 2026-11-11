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

- Use `NativeModulus::new()` when overflow itself represents reduction modulo the full word range.
- Use `PowOf2Modulus::new(value)` for a representable power-of-two modulus.
- Use `BarrettModulus::new(value)` when multiplication and repeated reduction are required for a modulus in the supported Barrett range.
- Use `CompactModulus::new(value)` or `UintModulus::new(value)` for their smaller basic-operation sets.

For constant parameter descriptions, use `ModulusConfig<M>` with Native, PowOf2 or Barrett and prepare it with `M::try_from(config)`. The conversion checks the selected representation and its range, returning `ModulusConfigError` on failure; it does not establish primality or NTT compatibility.

Use `BarrettModulus::try_new(value)` to report an invalid range without panicking. Use [`BarrettModulus::from_parts`](src/barrett/mod.rs) when the caller already has the validated modulus and its correct little-endian reciprocal. Direct construction or `.0` updates of `CompactModulus` and `UintModulus` must preserve their documented ranges.

## Prime preparation

`is_prime_u64(value)` is a deterministic primality test over the complete u64
range, intended for public parameter construction. It does not change the
contracts of the reducer constructors or `FieldContext`: those still do not
prove primality. Primality alone does not establish NTT compatibility or a
cryptographic security level.

## Features

- `derive` re-exports the `Barrett` derive macro for compile-time constant moduli. See [`primus_barrett_derive`](../primus_barrett_derive/README.md).
- `simd` enables nightly portable-SIMD kernels and slice dispatch. When `derive` is also enabled, generated Barrett contexts use the corresponding SIMD paths.

Both features are disabled by default. The `simd` feature requires a nightly Rust toolchain.

Stable builds can also select supported x86_64 kernels; disabling `simd` does not imply scalar-only machine code. Scalar and accelerated paths have the same arithmetic contracts. Performance depends on the CPU and workload; see the [benchmark guide](benches/README.md).

## Arithmetic contracts

The operation traits, input ranges, output ranges, and slice-length requirements come from `primus_reduce`.

- Canonical operations generally require canonical residues unless their trait or concrete implementation documents a wider input domain. Barrett dot products accept each operand below `2^(T::BITS - 2)`, including residues from another Barrett modulus larger than the destination; both slice and iterator forms return canonical residues.
- Lazy operations return representatives in `[0, 2 * modulus)` and require a final once-reduction before canonical use.
- Low-level slice kernels may use `debug_assert*!` for shape diagnostics; release callers must uphold the documented length contracts.
- `FieldContext` is a capability marker. It does not prove primality or guarantee that every nonzero value is invertible.
- `EncodeSigned` converts coefficients with unsigned magnitude less than the explicit modulus; Native accepts every signed value. Slice conversion checks equal input/output lengths. This conversion applies no plaintext scaling.
- `ReduceDotProductSigned` combines bounded signed coefficients and canonical residues for Native, PowOf2, Barrett and derived Barrett. It checks equal slice lengths and returns zero for empty inputs.

## Prepared modulus switching

All five modulus types and derived Barrett contexts implement `primus_reduce::PrepareModulusSwitch`. Construct `source.prepare_switch_to(target)` once and reuse its `switch` or `switch_map` methods. `ModulusSwitch::new(source, target)` is also available; both forms follow the same [rounding and batch contracts](../primus_reduce/README.md#prepared-modulus-switching).

```rust
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::PrepareModulusSwitch;

let conversion = BarrettModulus::new(97u32).prepare_switch_to(NativeModulus::new());
let residue = conversion.switch(48);
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
