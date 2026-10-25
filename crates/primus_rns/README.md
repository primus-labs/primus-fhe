# primus_rns

English | [简体中文](README.zh_CN.md)

`primus_rns` provides residue-number-system bases, CRT composition and decomposition, base conversion, and the hybrid `Q`/`P` operations used by [Primus FHE](../../README.md). Its allocation-free batched paths operate on flat slices with caller-owned reusable workspace.

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, data layouts, and numerical contracts are unstable and may change incompatibly at any time.

## Main types

| Type | Role |
| --- | --- |
| `Residues<S>` | One value represented under an ordered RNS basis |
| `ResidueFactors<S>` | Precomputed multiplication factors for one value under an ordered RNS basis |
| `RNSBase<T, M>` | A non-empty, pairwise-coprime modulus basis and its CRT precomputations |
| `BaseConverter<T, M>` | Precomputed fast or corrected conversion between two RNS bases |
| `CorrectedConversionWorkspace<T>` | Reusable workspace for corrected batched conversion |
| `HybridRNSPartitioning` | Fixed full-`Q` partition rule shared across modulus-chain levels |
| `HybridRNS<T, M>` | Bases and precomputations for one active hybrid-RNS level |
| `HybridRNSPartition<T, M>` | One contiguous `Q` partition and its approximate ModUp converter |

`T` is an unsigned FHE integer type. `M` is a `primus_reduce::FieldContext<T>`; [`BarrettModulus`](../primus_modulus/README.md) is the usual modulus implementation for repeated polynomial operations.

## Example

`Residues<S>` stores one value as canonical residues in basis order, using owned or borrowed storage. It does not retain or validate the basis; batch APIs use slices.

`ResidueFactors<S>` stores one precomputed multiplication factor per modulus in basis order. Each factor must match its corresponding modulus; the wrapper does not validate precomputations. Use `decompose_factors` to prepare factors for scaled-decomposition operations.

```rust
use primus_modulus::BarrettModulus;
use primus_rns::{RNSBase, Residues};

let moduli = [3_u64, 5, 7].map(BarrettModulus::new);
let base = RNSBase::new(&moduli).unwrap();

let value = base.compose(Residues(&[2, 4, 6]));
assert_eq!(value.digits(), &[104]);
assert_eq!(base.decompose(value.view()).as_ref(), [2, 4, 6]);
```

`compose` returns the canonical representative in `[0, Q)`, where `Q` is the product of the basis moduli.

## Layout

Batched residues are always modulus-major. For `k` values and moduli `q_0, ..., q_(n-1)`, a slice of length `n * k` is arranged as

```text
[a_0 mod q_0, ..., a_(k-1) mod q_0,
 a_0 mod q_1, ..., a_(k-1) mod q_1,
 ...]
```

Batched big integers use the opposite grouping: each value occupies one contiguous, fixed-width, little-endian limb chunk. The chunk width is `RNSBase::big_uint_value_len()`.

[`CrtPolynomial`](../primus_poly/README.md) uses the same modulus-major coefficient layout. Pass its coefficient slice to the batched APIs, with the polynomial length as the value count; no rearrangement is needed. `primus_rns` does not depend on polynomial container types.

## RNS bases

`RNSBase::new` constructs a base from a nonempty slice of pairwise-coprime moduli; `from_owned_moduli` takes ownership of their vector. Construction and extension return `RnsError` for invalid bases.

Cloning an `RNSBase` shares immutable precomputations without copying buffers. `extend` / `extend_with` create a new base and leave the original unchanged. Reuse a prepared base rather than independently constructing the same basis.

Use `compose*` and `decompose*` for CRT conversion. Single-value operations accept borrowed `Residues` / `BigUint` views; obtain these through `view()` or `view_mut()` on owned storage. Single-value decomposition does not impose Q's limb width; the modulus implementation's limb-slice contract still applies. Batched big integers use the fixed width described above. Empty batches perform no writes, with the documented output, factor and scratch lengths still required.

`wrapping_decompose*` performs centered lifting from a smaller modulus `t`: values below `ceil(t / 2)` are nonnegative and the rest are negative representatives. For `t = 2`, both `0` and `1` are preserved, so `1` is not lifted as `-1`.

The two `add_*decompose_small_values_scaled_assign` operations add weighted residues to an existing canonical accumulator without clearing or allocating temporary storage. Factors must belong to the matching moduli. Complete operation contracts are in the [base API](src/base).

## Base conversion

`BaseConverter::new` shares the prepared input and output bases; `from_owned_bases` takes ownership of their handles. Cloning a multi-modulus converter copies its conversion matrix, so reuse the converter in repeated paths.

Conversion is intended for runtime or derived Barrett contexts. Multi-modulus conversion requires cross-modulus dot products accepting source residues even when they exceed the destination modulus; Barrett accepts operands below `2^(T::BITS - 2)`. Custom contexts must satisfy the [converter arithmetic contract](src/converter/fast.rs); `FieldContext` alone does not establish these ranges.

The two conversion families have different mathematical contracts:

- `fast_convert` and `fast_convert_array` compute a SEAL-style approximate CRT lift. With a multi-modulus input basis, the result represents `x + kQ` for some integer `k`; it is not generally the canonical `x mod p_j`. This is suitable only when the surrounding algorithm cancels or accepts the multiple-of-`Q` term. A single-modulus input uses exact direct reduction.
- `corrected_convert_array` applies a quotient correction, interprets the input through its centered representative in `[-Q/2, Q/2)`, and requires exactly one output modulus. For multi-modulus inputs, correction uses `f64`, so values near the centered boundary may differ by one multiple of `Q` modulo the output modulus; applications requiring exactness there need a higher-precision method. See the [corrected-conversion API](src/converter/corrected.rs).

Create a `CorrectedConversionWorkspace` through `corrected_conversion_workspace` and reuse it with the same converter and length. Fast conversion accepts a scratch slice sized by `fast_convert_scratch_len` or `fast_convert_array_scratch_len`. Empty batches perform no writes; corrected conversion still requires one output modulus and a workspace of the matching shape. Each concurrent operation needs separate mutable workspace.

## Hybrid RNS

`HybridRNS` combines a ciphertext basis `Q` with an auxiliary basis `P` and stores the complete basis in `Q || P` order. `HybridRNSPartitioning` derives a fixed maximum partition size `alpha` from the full `Q` basis and requested digit count `dnum`:

```text
alpha = ceil(full_q_moduli_count / dnum)
```

The fixed size must produce exactly `dnum` non-empty partitions. For example, five `Q` moduli with `dnum = 3` produce ranges `[0..2, 2..4, 4..5]`; requesting `dnum = 4` is rejected because the same fixed size would produce only three partitions.

Use `HybridRNS::from_partitioning` at shorter, ordered-prefix levels of the same modulus chain so key-compatible partition boundaries remain fixed. The constructor validates the active modulus count; the owner of the modulus chain must preserve the prefix relationship.

Each partition supports approximate ModUp into `Q || P`; streaming ModUp emits only converted complement limbs, leaving the caller to supply unchanged partition limbs. ModDown converts the `P` correction into `Q`, subtracts it, and multiplies by `P^-1 mod q_i`.

For scheme-specific corrections, use `approx_convert_p_to_q_to` followed by `approx_mod_down_from_correction_q_assign`; the caller owns the correction's source, sign and scaling in the same ordered Q basis. This is not automatically a BFV, BGV or CKKS modulus-reduction rule. Zero-length Hybrid operations perform no writes or streaming callbacks. See the [hybrid APIs](src/hybrid).

## Caller contracts and workspace

- Input residues supplied to arithmetic and base-conversion kernels must be canonical for their corresponding moduli unless the method documents a wider range.
- Moduli combined in one basis, including `Q || P`, must be pairwise coprime.
- Slice lengths and modulus-major ordering must match the selected base and value count (polynomial length for Hybrid operations).
- Reuse converter workspaces and scratch buffers outside hot loops. The batched APIs perform no internal allocation once their output and workspace are provided.
- Not every low-level operation validates these conditions in release builds; uphold its documented contract.

## SIMD feature

The optional `simd` feature enables portable-SIMD small-value and modular arithmetic paths. It is disabled by default and requires a nightly Rust toolchain.

## Testing and benchmarks

```text
cargo test -p primus_rns
cargo bench -p primus_rns --bench decompose
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
