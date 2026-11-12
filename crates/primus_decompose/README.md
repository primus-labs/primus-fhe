# primus_decompose

English | [简体中文](README.zh_CN.md)

`primus_decompose` provides approximate signed radix decomposition for [Primus FHE](../../README.md). It separates reusable basis precomputation from single-value and batched digit extraction, for gadget products and key switching.

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, representations, and numerical contracts may change incompatibly.

## Choose a basis

Use the [primitive basis](src/primitive/basis.rs) for single-limb inputs with
an explicit modulus or the implicit native modulus `2^T::BITS`. Use the
[BigUint basis](src/big_integer/basis.rs) for fixed-width little-endian integers
from [`primus_integer`](../primus_integer/README.md). Construct a basis once and
reuse it.

[Checked parameters](src/parameters.rs) describe the radix logarithm and
positive retained-level count. Use `ApproxSignedBasis::try_from((config, modulus))`
to bind a `DecompositionConfig` to the modulus. The basis
checks that the choices fit the modulus and limb width. Selecting all full
levels can still leave low bits to round away.

## Digits and reconstruction

The signed digits lie in `[-B/2, B/2)` for radix `B`. The decomposition and
weight iterators both start at the lowest retained level. The weighted sum
approximates the original residue within `approximate_error_bound()` in
circular distance. Use basis initialization for the correct representative
and rounding carry.

| Output | Representation of a signed digit |
| --- | --- |
| Primitive `decompose*` | Canonical residue modulo the input modulus |
| BigUint `decompose_slice_to` | Full-width canonical residue modulo the input modulus |
| BigUint `decompose_radix*` | One limb modulo `B`. For example, `255` represents `-1` at radix `256`. Interpret the digit as centered before lifting. |

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

For a primitive power-of-two modulus, use `init_carry_slice` with the original
input, saving the adjustment buffer. For other moduli, use
`init_value_carry_slice_to`. Both paths preserve the ascending carry protocol.

## BigUint workflow and layout

The BigUint basis always requires input initialization. Batch buffers are
value-major, with exactly `big_uint_value_len()` little-endian limbs per
input and per full-width digit. Compact radix output uses one limb per value.
See the [basis](src/big_integer/basis.rs) and
[digit output](src/big_integer/common.rs) contracts. Convert modulus-major
residues with [`primus_rns`](../primus_rns/README.md) before integer decomposition.

## Caller contracts and features

Pass canonical inputs and complete buffers. Initialize each new batch, keep
the adjusted inputs as returned, and advance all levels with the same carry
buffer. The slice operations overwrite digits and reuse the supplied storage.
The default feature set is empty. The optional `simd` feature forwards to
`primus_integer/simd` and requires nightly Rust.

See the [benchmark guide](benches/README.md) and the workspace
[testing guide](../../guides/development/testing.md).

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
