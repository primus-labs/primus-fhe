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
| `CenteredBaseConverter` | Exact centered conversion for supported u64 bases |
| `HpsRns` | Prepared HPS coefficient operations |
| `HybridRNS` and `HybridRNSPartitioning` | One active level and its fixed full-chain partition rule |

[`BarrettModulus`](../primus_modulus/README.md) is the usual context for
repeated polynomial operations.

## Example

`Residues<S>` borrows or owns one value's canonical residues in basis order.
Supply the matching basis to the operation. Use `decompose_factors` to prepare
`ResidueFactors<S>` for scaled decomposition.

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

`RNSBase::new` checks that the basis is nonempty and its moduli are pairwise
coprime. Reuse the prepared basis and use `prefix(count)` for a nonempty
ordered chain prefix. Custom contexts must satisfy the
[basis contract](src/base/mod.rs), including the modulus range for Shoup
factors.

Use `compose*` and `decompose*` for CRT conversion. For centered lifts from a
small modulus, use [`wrapping_decompose*`](src/base/small.rs). At modulus two,
this preserves both binary values. Scaled accumulation methods in the same
API add to a canonical accumulator and use factors for the matching basis.

## Base conversion

Construct a converter from prepared bases and reuse its workspace or scratch
for the matching batch size. Each concurrent operation needs separate mutable
storage.

| Operation | Meaning |
| --- | --- |
| [`fast_convert*`](src/converter/fast.rs) | Approximate CRT lift of `x + kQ` from a multi-modulus basis. The caller's algorithm must allow the extra multiple of `Q`. A single-modulus input uses exact reduction. |
| [`corrected_convert_array`](src/converter/corrected.rs) | Centered correction with one output modulus. The floating correction near a half boundary can differ by a multiple of `Q`. |
| [`CenteredBaseConverter`](src/converter/centered.rs) | Exact centered conversion for odd u64 bases below `2^62`, with one or more output moduli. |

Multi-modulus conversion uses cross-modulus dot products. Operands can exceed
the destination modulus. Barrett accepts operands below `2^(T::BITS - 2)`.
Custom contexts must meet the [conversion range contract](src/converter/fast.rs).

### HPS coefficient operations

[`HpsRns`](src/hps.rs) prepares disjoint, pairwise-coprime odd u64 bases below
`2^62` and a positive scale `t`. With reusable workspace it supports exact
centered expansion, P/Q prescaling with a bounded one-sided residual, and exact
`nearest(t*z/P) mod Q` from coherent Q/P residues. The
[BFV contract](../../guides/development/bfv-evaluation.md#hpspoverq-backend)
covers the consuming algorithm, auxiliary basis and error conditions.

## Hybrid RNS

`HybridRNS` combines the ciphertext basis `Q` and auxiliary basis `P` in
`Q || P` order. Use the same `HybridRNSPartitioning` across nonempty ordered
prefixes of one modulus chain to preserve key-compatible boundaries. The
[constructor contract](src/hybrid/construction.rs) describes valid digit counts
and active levels.

Approximate ModUp lifts a partition into `Q || P`. Streaming ModUp emits only
converted complement limbs, so callers supply the unchanged partition limbs.
Approximate ModDown subtracts a correction converted from `P` to `Q`, then
multiplies by `P^-1 mod q_i`. Scheme-specific corrections must have the matching
source, sign, scale and ordered Q basis. See [Hybrid APIs](src/hybrid) and
[native BFV/BGV Hybrid keys](../../guides/development/native-hybrid-keys.md) for
the exact centered correction used by those schemes.

## Caller contracts and workspace

Pass canonical residues and complete buffers in basis order. Combined bases
must be pairwise coprime. Match the method's output and scratch shapes to the
batch size. Use independent mutable workspace for concurrent calls.

## SIMD feature and benchmarks

The optional `simd` feature enables nightly portable SIMD for small-value and
modular arithmetic paths. It is off by default. See the
[decomposition benchmark](benches/decompose.rs) for its workloads.

```sh
cargo bench -p primus_rns --bench decompose
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
