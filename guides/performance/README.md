# Performance decisions and historical evidence

English | [简体中文](README.zh_CN.md)

These reports preserve decisions, numerical limits and adverse measurements.
**Historical results are not current-HEAD validation or security guarantees.**
Current configuration and commands belong to the [development guide](../development/README.md),
[TFHE benchmarks](../development/testing.md#tfhe-benchmarks) and
[LUT benchmarks](../../../primus_high_prec_lut/guides/development/testing.md#high-precision-lut-benchmarks).

| Report | Purpose |
| --- | --- |
| [LUT presets](../../../primus_high_prec_lut/guides/performance/ntru-lut-presets.md) | Current 28-export scope; LowPrec/HighPrec parameter choices and unresolved DFR/split-FFT limits. |
| [NTRU projection](ntru-projection-fusion.md) | Configurable strategies, key/scratch costs, negative binary gate and Fourier first-pair sharing. Historical gadgets differ from current presets. |
| [Cross-library PBS/CBS/EBS](bootstrap-functional-comparison.md) | 2026-10-11–13 library/algorithm/parameter comparisons. Later Primus changes are not backfilled into old rankings. |
| [Sparse arithmetic](sparse-arithmetic.md) | Dispatch bounds, aggregation evidence and reusable input-batch kernels. |
| [OMR scheduling](../../../primus_omr/guides/performance/omr-scheduling.md) | Independent application: detection/retrieval throughput, worker scheduling and workspace costs. |
| [Sparse layout/batching](sparse-layout-and-batching.md) | Four-input schedule, descriptor ownership, tile/streaming/layout counterexamples; old pruned-LUT results are not current-tree evidence. |
| [Fourier GLWE key generation](fourier-glwe-keygen.md) | Exact native-row repair costs, unchanged online storage, and limits of pre-repair results. |
| [GLWE square SS](glwe-square-ss.md) | Rank-one NTT square material, complete CBS/CMux measurements and unchanged workspace costs. |
| [Fourier first write](fourier-first-write.md) | Why clear-then-accumulate remains; all 54 build-valid pairs include adverse and FFT-plan-mismatched results. |

## Reading and remeasuring

Compare the same revision, actual binary, CPU, features, parameters and complete
operation. Stage speedups, fewer allocations and equal buffer lengths alone do
not establish complete-request gains. Measure one request per iteration; keep
unrelated setup/validation outside timing and construction costs separate.
Preserve adverse rounds and unchanged-path controls: process confidence intervals
do not capture process-to-process variation.

Historical CPU4/8 results are two cache groups of **one** Ryzen9 9955HX3D,
not independent platforms. Elapsed time cannot diagnose cache writeback or
bandwidth; allocation traffic, retained heap, peak and RSS are distinct.

[Data files](data/) retain original samples or compact metadata, with their own
units and provenance. Do not rename old workloads or rewrite recorded parameter
values to match current APIs. They identify historical measurements, not promised
standalone replay bundles; removed adapters/binaries are not maintained.
Contract changes require fresh validation and complete timings. No committed
report depends on local `docs/` or temporary source archives.

Keep datasets with a surviving comparison or implementation decision, rather
than every old experiment. Superseded NTRU matrices and single-run reference
samples have been retired to Git; an old link alone is not a retention reason.
