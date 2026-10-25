# Factor benchmarks

> [!WARNING]
> Part of the experimental [Primus FHE](../../../README.md) workspace; APIs and numerical contracts may change incompatibly.

[`shoup_factor`](shoup_factor.rs) measures canonical precomputed multiplication for u32 and u64: output multiplication, in-place multiplication, multiply-add and multiply-subtract. The source defines parameters, deterministic inputs and Criterion settings.

Run the target, or smoke-check it without statistical sampling:

```sh
cargo bench -p primus_factor --bench shoup_factor
cargo bench -p primus_factor --bench shoup_factor -- --test
cargo +nightly bench -p primus_factor --bench shoup_factor --features simd
```

The corresponding broadcast cases in [modulus `slice_arithmetic`](../../primus_modulus/benches/slice_arithmetic.rs) use matched moduli, multipliers, inputs and lengths. Compare the same operations to assess precomputation benefits. The extra u64 modulus `2^63-1` exercises Shoup's upper range; prime moduli are not required.

Factor construction and allocation are outside timing, so these cases do not measure the break-even reuse count. Repeated in-place results stay canonical without resets. Throughput counts elements; buffers are reused, rather than traversing a complete ciphertext/RNS workload.

Keep host, CPU, toolchain and features fixed; compare stable and nightly builds separately. Default builds may use native kernels or compiler vectorization. Lazy and single-value operations are outside this target's scope.
