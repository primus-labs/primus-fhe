# Modulus benchmarks

> [!WARNING]
> Part of the experimental [Primus FHE](../../../README.md) workspace; APIs and numerical contracts may change incompatibly.

Choose a target by the operation you want to measure. Each linked source defines its parameters, deterministic inputs and Criterion settings.

| Target | Workload |
| --- | --- |
| [scalar_moduli](scalar_moduli.rs) | Scalar reducer comparisons and canonical/lazy Barrett multiplication and reduction |
| [slice_moduli](slice_moduli.rs) | Compact versus Uint add/sub, and native versus power-of-two add, multiply and dot product |
| [barrett_slice](barrett_slice.rs) | Canonical/lazy multiplication, dot products, batch inversion, and PBS multiply-add dispatch |
| [derived_mac](derived_mac.rs) | Constant-modulus multiply-add versus its fallback; requires `derive` |
| [slice_arithmetic](slice_arithmetic.rs) | Native/Barrett add/sub and negation with a tail, plus broadcast multiplication matched to Shoup factor |
| [signed_encoding](signed_encoding.rs) | Bounded signed-to-residue conversion |
| [signed_dot_product](signed_dot_product.rs) | Signed versus pre-encoded ternary dot products |
| [modulus_switch](modulus_switch.rs) | Prepared scalar and batch modulus switching |

Run one target, or smoke-check it without statistical sampling:

```sh
cargo bench -p primus_modulus --bench slice_arithmetic
cargo bench -p primus_modulus --bench slice_arithmetic -- --test
cargo bench -p primus_modulus --bench scalar_moduli -- 'barrett/scalar'
cargo +nightly bench -p primus_modulus --bench slice_arithmetic --features simd
cargo bench -p primus_modulus --bench derived_mac --features derive
```

Setup and allocation are outside timing; slice throughput counts elements, not bytes. Reused-buffer cases do not measure a complete ciphertext/RNS traversal or parameter preparation.

`barrett_slice` keeps both word widths, uses lengths 31/32/33 for the u64 multiply-add dispatch boundary, and includes moduli on both sides of the IFMA cutoff. `slice_moduli` keeps paired reducer comparisons at length 4096 and adds representative u64 lengths for multiply and dot product scaling.

`signed_dot_product` compares the signed path with pre-encoded operands at lengths 16, 1024 and 1025. The Barrett portable-SIMD build covers scalar fallback, full blocks and a scalar tail. Encoding is outside timing.

`slice_arithmetic` and [Shoup factor benchmarks](../../primus_factor/benches/README.md) have matched broadcast-multiplication cases. Compare those operations, rather than elementwise multiplication, to assess precomputation benefits; factor construction is outside timing.

Keep machine, features and toolchain fixed. Compare stable and nightly builds separately; a default build may use native kernels or compiler vectorization. These microbenchmarks do not establish complete PBS performance.
