# primus_decompose

English | [简体中文](README.zh_CN.md)

`primus_decompose` provides approximate signed radix decomposition for [Primus FHE](../../README.md). It separates reusable basis precomputation from single-value and batched digit extraction, for gadget products and key switching.

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, representations, and numerical contracts may change incompatibly.

## Core types

| Type | Role |
| --- | --- |
| `DecompositionBaseLog` / `DecompositionLevelCount` | Checked radix logarithm and positive retained-level count |
| `DecompositionConfig` | Radix and retained-level choices; `ApproxSignedBasis::try_from((config, modulus))` binds the modulus |
| `primitive::ApproxSignedBasis<T>` | Single-limb inputs with an explicit modulus or the implicit native modulus `2^T::BITS` |
| `big_integer::BigUintApproxSignedBasis<T>` | Fixed-width, multi-limb inputs with an explicit integer modulus |
| `OnceSignedDecomposer`, `OnceBigUintSignedDecomposer` | Extract one retained level; obtained from the corresponding basis's `decomposer_iter()` |
| `ApproxSignedBasisError` | Invalid construction parameters, returned by `try_new` and `TryFrom` |

`T: FheUint` is the unsigned coefficient type for the primitive basis and the limb type for the BigUint basis. `BigUint` comes from [`primus_integer`](../primus_integer/README.md), not a dynamically sized integer library. Construct a basis once and reuse it.

## Mathematical contract

For `B = 2^log_basis`, `L = level_count()` and `d = drop_bits()`, decomposition produces signed digits with weights:

```text
-B/2 <= digit_i < B/2
weight_i = 2^d * B^i                  (0 <= i < L)
reconstructed = sum(digit_i * weight_i) mod modulus
```

Both `decomposer_iter()` and `scalar_iter()` visit levels from the lowest retained level to the highest. The circular distance between the input and its reconstruction is at most `approximate_error_bound()`: zero when `d == 0`, otherwise `2^(d - 1)`.

Initialization selects the internal representative and initial rounding carry. Discarded bits are rounded to nearest, with half-way cases rounded up in that representative. In particular, native inputs recompose to `round_half_up(input / 2^d) * 2^d` modulo `2^T::BITS`. For other moduli, do not replace initialization with rounding the canonical input: the representative adjustment is part of correctness.

The output encoding depends on the operation:

| Operation | Encoding of a mathematical digit `z` |
| --- | --- |
| Primitive `decompose*` | One canonical residue modulo `q`; negative `z` becomes `q + z`, or its native wrapping representation |
| BigUint `decompose_slice_to` | A full-width canonical residue modulo `Q`; negative `z` becomes `Q + z` |
| BigUint `decompose_radix*` | One limb in `[0, B)` encoding `z mod B`; decode `u >= B/2` as `u - B` |

`decompose_radix*` represents a **signed** digit modulo the radix. For example, with `B = 256`, output `255` means `-1`, not positive `255`. Interpret it as a centered digit before lifting to another modulus.

## Construction and retained levels

`DecompositionBaseLog` checks `log_basis >= 2`; `DecompositionLevelCount` checks `L >= 1`. Construct them with `new`, `try_new` or `TryFrom`, and read the integer with `.get()`. They add no fixed upper bounds. Basis constructors and their `log_basis()` / `level_count()` accessors use these types.

Both bases additionally require `log_basis < T::BITS`, a modulus at least `B`, and a retained count that fits the decomposition width. A multi-limb basis can have more levels than one limb has bits. Basis `new` panics on these contextual errors; `try_new` returns `ApproxSignedBasisError`.

`DecompositionConfig { log_basis, level_count }` keeps these choices independent of the modulus. `ApproxSignedBasis::<u32>::try_from((config, None))` prepares a native basis, while `ApproxSignedBasis::try_from((config, Some(q)))` uses an explicit modulus. The config contains choices, not precomputed storage.

The decomposition width `m` differs between representations:

| Basis and modulus | Width `m` |
| --- | --- |
| Primitive, `None` | `T::BITS`, with implicit modulus `2^T::BITS` |
| Primitive, explicit power of two `q` | `log2(q)` |
| Primitive, other explicit `q` | `bit_width(q)` |
| BigUint, any explicit `Q` | `bit_width(Q)`, **including powers of two** |

The full level count is `floor(m / log_basis)`. The constructor argument `level_count` is an optional **retained level count**: `Some(L)` requires `1 <= L <= full_level_count`, while `None` uses all full levels. In both cases, `drop_bits = m - L * log_basis`, so even `None` can discard low bits when `m` is not divisible by `log_basis`.

A BigUint modulus must have a nonempty little-endian limb slice with a nonzero most-significant limb. The basis owns a copy. Inputs use exactly that same limb count, including leading zero limbs when the input value is small.

## Primitive workflow

Initialize a batch once, then pass the same adjusted values and advancing carry buffer through every level. Consume each level before overwriting its output:

```rust
use primus_decompose::{DecompositionBaseLog, primitive::ApproxSignedBasis};

let basis = ApproxSignedBasis::new(Some(97_u32), DecompositionBaseLog::new(2), None);
let values = [42_u32, 96];
let mut adjusted = [0_u32; 2];
let mut carries = [false; 2];
let mut digits = [0_u32; 2];
let mut reconstructed = [0_u32; 2];

basis.init_value_carry_slice_to(&values, &mut adjusted, &mut carries);
for (decomposer, weight) in basis.decomposer_iter().zip(basis.scalar_iter()) {
    decomposer.decompose_slice_to(&adjusted, &mut digits, &mut carries);
    // These small example parameters make the intermediate products fit in u32.
    for (sum, &digit) in reconstructed.iter_mut().zip(&digits) {
        *sum = (*sum + digit * weight) % 97;
    }
}

assert_eq!(basis.drop_bits(), 1);
assert_eq!(reconstructed, [42, 0]); // Circular errors modulo 97: 0 and 1.
```

Power-of-two primitive inputs need no adjusted-value buffer: use `init_carry_slice` and pass the original inputs through every level. It panics for non-power-of-two moduli; use `init_value_carry_slice_to` for those. Scalar processing uses `init_value_carry` followed by `decompose` with the same carry protocol. See the [primitive basis API](src/primitive/basis.rs).

## BigUint workflow and layout

For `N` values and `W = big_uint_value_len()` limbs per value, full-width buffers contain `N * W` limbs in **value-major**, little-endian order:

```text
[value_0_low, ..., value_0_high, value_1_low, ..., value_1_high, ...]
```

Carry buffers contain `N` booleans. Full-width digit outputs contain `N * W` limbs; compact `decompose_radix_slice_to` outputs contain only `N` limbs. BigUint initialization is required even when `Q` is a power of two.

Use `init_value_carry_slice_to` and `decomposer_iter()` with the same ascending-level carry protocol. For a single value, use one full-width value buffer and a one-element carry slice with the same batch APIs. Exact buffer contracts are in the [BigUint basis API](src/big_integer/basis.rs) and [digit-output API](src/big_integer/common.rs).

RNS/CRT residues use modulus-major storage, not this value-major limb layout. Convert them with [`primus_rns`](../primus_rns/README.md) before integer decomposition.

## Caller contracts and allocation

- Original inputs must be canonical: `[0, q)` or `[0, Q)`. Every bit pattern is valid for the primitive native modulus. These methods do not reduce inputs.
- Adjusted inputs are internal bit representations, not necessarily canonical residues. Keep them unchanged throughout decomposition; do not reduce them.
- Apply every operator in ascending level order, without skipping levels or resetting carry. A zero digit can still produce a carry. Start each new input batch with initialization, not with the previous batch's final carries.
- Primitive value, output and carry slices must have equal lengths. BigUint buffers must follow the exact shapes above. The slice methods do not validate these layouts in release builds.
- Slice methods overwrite outputs and update carries; they do not accumulate digits. BigUint `init_value_carry_slice_assign` also overwrites the original values.
- Constructors allocate precomputation storage. Decomposition and slice initialization reuse caller-owned buffers without allocating internally. BigUint `approximate_error_bound` allocates a result for precision diagnostics.

## Features and further reading

The default feature set is empty. The optional `simd` feature forwards to `primus_integer/simd` and requires nightly Rust. It does not select a separate decomposition backend; the loops can also benefit from compiler auto-vectorization.

Public contracts are documented in the [API sources](src). See the [benchmark guide](benches/README.md) for workloads and commands, and the workspace [testing guide](../../guides/development/testing.md) for validation entry points.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
