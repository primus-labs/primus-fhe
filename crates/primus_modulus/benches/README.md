# Modulus benchmarks

> [!WARNING]
> Part of the experimental [Primus FHE](../../../README.md) workspace; APIs and numerical contracts may change incompatibly.

Choose a target by the operation you want to measure. Each linked source defines its parameters, deterministic inputs and Criterion settings.

| Target | Workload |
| --- | --- |
| [scalar_moduli](scalar_moduli.rs) | Scalar arithmetic across modulus types |
| [barrett_scalar](barrett_scalar.rs) | Canonical/lazy Barrett multiplication and reduction |
| [slice_moduli](slice_moduli.rs) | Slice arithmetic across modulus types |
| [barrett_slice](barrett_slice.rs) | Canonical/lazy multiplication, dot products and batch inversion |
| [derived_mac](derived_mac.rs) | Constant-modulus multiply-add versus its fallback; requires `derive` |
| [slice_arithmetic](slice_arithmetic.rs) | Native/Barrett add/sub, negation and broadcast multiplication |
| [signed_encoding](signed_encoding.rs) | Bounded signed-to-residue conversion |
| [signed_dot_product](signed_dot_product.rs) | Signed versus pre-encoded ternary dot products |
| [modulus_switch](modulus_switch.rs) | Prepared scalar and batch modulus switching |

Run one target, or smoke-check it without statistical sampling:

```sh
cargo bench -p primus_modulus --bench slice_arithmetic
cargo bench -p primus_modulus --bench slice_arithmetic -- --test
cargo +nightly bench -p primus_modulus --bench slice_arithmetic --features simd
cargo bench -p primus_modulus --bench derived_mac --features derive
```

Setup and allocation are outside timing; slice throughput counts elements, not bytes. Reused-buffer cases do not measure a complete ciphertext/RNS traversal or parameter preparation.

`slice_arithmetic` and [Shoup factor benchmarks](../../primus_factor/benches/README.md) have matched broadcast-multiplication cases. Compare those operations, rather than elementwise multiplication, to assess precomputation benefits; factor construction is outside timing.

Keep machine, features and toolchain fixed. Compare stable and nightly builds separately; a default build may use native kernels or compiler vectorization. These microbenchmarks do not establish complete PBS performance.
