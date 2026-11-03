# Performance decisions and historical evidence

English | [简体中文](README.zh_CN.md)

Start with the decision relevant to your workload. **Historical timings are not
current-HEAD validation or security/DFR guarantees.** The index is bilingual;
topic language is listed below, and measurement data is shared once.
Current usage and commands belong to the [development guide](../development/README.md)
and [benchmark guide](../development/testing.md#tfhe-benchmarks).

| Topic | Language | What remains useful |
| --- | --- | --- |
| [BFV coefficient workflow](bfv-leveled-coefficients.md) | English | Exact rounded prime-drop resources and complete coefficient-request costs |
| [Sparse arithmetic and scheduling](sparse-arithmetic.md) | English | Current grouping, canonical NTT boundaries, 16 KiB tiles, 4/2/1 ownership and retained negative controls |
| [NTRU projection](ntru-projection-fusion.md) | English | Four NTT strategies, Fourier paired/sharing costs and historical binary full-request failure gate |
| [Fourier GLWE key generation](fourier-glwe-keygen.md) | 中文 | Exact native-row repair, key replacement, setup/storage costs and floating-point limits |
| [GLWE square SS](glwe-square-ss.md) | 中文 | Rank-one NTT material savings, complete CBS/CMux gains and regressions |
| [PBS/CBS/EBS references](bootstrap-functional-comparison.md) | 中文 | Historical algorithms, parameter differences and process means; unrepaired Primus GLWE Fourier times retired |
| [First-product overwrite](fourier-first-write.md) | English | Short historical reason to keep clear-then-accumulate; not evidence for today's pipeline |
| [LUT presets](../../../primus_high_prec_lut/guides/performance/ntru-lut-presets.md) | English | Independent library's request-specific parameters and numerical limits |
| [OMR scheduling](../../../primus_omr/guides/performance/omr-scheduling.md) | English | Independent application's detection/retrieval throughput, workers and workspace costs |

## Comparing and remeasuring

Use the same algorithm, revision/actual binary, CPU, features, parameters and
complete operation. Stage speedups or fewer allocations do not establish full
request gains. Keep setup/validation outside one-request timing, construction
costs separate, and adverse rounds/unchanged-path controls. Process intervals
do not measure between-process variation.

CPU4/8 records are two L3 groups of **one** Ryzen9 9955HX3D, not independent
platforms. Time alone does not diagnose cache writeback/bandwidth. Requested
heap, allocation traffic, peak and RSS have different boundaries.

[Data](data/) retains the necessary process summaries, source/parameter identities
and selected original samples. Numerical/method contracts remain in rustdoc and
the [bootstrapping guide](../development/bootstrapping-contracts.md).
Old parameter names and values are not rewritten as current presets. Reports
identify measurements, not standalone replay kits; removed adapters/ELFs are not
maintained. No public report depends on local `docs/`.

Superseded raw matrices and duplicated chronology are recoverable at Git
`c6a6fcbe8dce15be5df83215611f39bdeda181ba`, for example:

```sh
git show c6a6fcbe:guides/performance/data/fourier-first-write-pairs.csv
```

New parameters, contracts, FFT plans or compilers need new validation/timing;
old favorable or adverse results are not silently replaced.
