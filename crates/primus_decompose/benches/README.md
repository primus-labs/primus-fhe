# primus_decompose benchmarks

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> [Primus FHE](../../../README.md) is experimental; its APIs and numerical contracts may change incompatibly.

## Workloads and commands

The [`decompose`](decompose.rs) target separates basis construction from online decomposition:

| Group | Work measured per iteration |
| --- | --- |
| `decompose/primitive/setup`, `decompose/big/setup` | Construct and drop one basis |
| `decompose/primitive/online`, `decompose/big/online` | Initialize one value or batch and extract every retained level |
| `decompose/pbs/` | Decompose one polynomial with GLWE/NTRU external-product profiles: `init` measures initialization, `levels` extracts all retained levels, and `full` measures both |

```text
cargo bench -p primus_decompose --bench decompose
cargo bench -p primus_decompose --bench decompose -- --test
cargo +nightly bench -p primus_decompose --bench decompose --features simd
```

Parameters and buffer setup are in the bench source. BigUint online cases measure compact radix-encoded digits used by DCRT consumers, with fixed strides 1/2/4 and runtime stride 3. Online cases reuse storage; the `levels` cases restore initial carries outside timing.

The `pbs` group uses fixed historical decomposition profiles, independent of current TFHE presets. These measurements cover decomposition, not an entire external product or PBS; adding separately timed stages does not replace measuring `full`.
