# Fourier first-product write

[Performance guide](README.md) · [Current benchmark commands](../development/testing.md#tfhe-benchmarks)

2026-10-07. **Retain clear-then-accumulate (F0).** First-product overwrite (F1)
improves measured binary PBS and classic CBS profiles, but mixed sparse CBS
results and process variability do not justify replacing the shared kernel.
This is an adoption decision, not proof that F1 intrinsically slows sparse CBS.
The candidate implementation and temporary benchmark were removed. Later torus
conversion and interleaved-FMA changes are outside this historical comparison;
these results are not a measurement of today's full Fourier pipeline.

The GLWE Fourier rows also predate the exact coefficient key-generation repair
and used the former unreduced representation. They are not a repaired-key baseline
or a parameter/security validation. See the [repair measurements](fourier-glwe-keygen.md);
this caveat does not reclassify NTRU measurements.

## Measurement scope

- Base commit: `494246cfd92a67d2f5854c62b55fa0c75fd97a6d`. F1 changes only GGSW
  Fourier accumulation: write the first product, then add later products;
  k-CMux initializes once across all controls. Decomposition, traversal order,
  inverse FFT and torus add-back are unchanged.
- AMD Ryzen 9 9955HX3D, CPU 4 (96 MiB L3 group) and CPU 8 (32 MiB group).
  These are two cores of one machine. Powersave/boost policy was unchanged;
  external activity was not isolated. No cache mechanism was established.
- rustc 1.98.1, LLVM 22.1.8, release, repository `target-cpu=native`,
  `rustfft,tfhe-fft`. No Primus nightly SIMD performance comparison.
- Complete KS→BR requests with native torus arithmetic. Keys, input, LUT,
  evaluator and output remain alive across callbacks; setup and verification
  are outside timing. One iteration is one request; MVB returns three outputs.
- Nine workloads × two versions × two CPUs × three rounds: **108 processes,
  3240 samples**. Each process uses 30 samples, 3 s warmup, 5 s measurement
  target and 10000 resamples. Round 2 reverses CPU/workload/version order.
- The default TfheFFT measured planner is retained. Plans match in 53/54 pairs;
  CPU 4 / u64 binary TfheFFT / round 2 cannot isolate an F1 effect.

| Workload | Geometry and decomposition |
| --- | --- |
| u32 binary PBS, both engines | n800/N1024, k1; BR log8/L3, KS log2/L13; t4 |
| u64 binary PBS, both engines | n866/N2048, k1; BR log23/L1, KS log3/L5; t32 |
| u64 ternary PBS, TfheFFT | n800/N1024, k1; full log8 BR/KS; t4 |
| u64 sparse PBS, TfheFFT | n728/h32/N1024, k1; full log8 BR/KS; 3 copies/64 buckets; t8 |
| u64 CBS, classic RustFFT and sparse TfheFFT | n728/h32/N1024; t4; output log8/L2; full log8 BR/KS/trace/scheme-switch; sparse 3 copies/64 buckets |
| u64 classic factorized MVB, TfheFFT | n728/h32/N1024; full log8 BR/KS; domain 8, 3 thresholds |

These historical arithmetic cost profiles are not security or failure-rate
certifications. CSV case IDs name these workloads, not current Cargo targets;
the experiment runner is not a maintained workspace benchmark.

## Results and decision

The [paired results](data/fourier-first-write-pairs.csv) retain all 54 valid
build comparisons, including adverse results and the plan-mismatched pair.
`case`, `cpu` and `round` identify a pair; `same_plans` marks FFT-plan agreement. F0/F1 means and medians are in
milliseconds; each change column is `100 × (F1/F0 - 1)`, so negative is faster.
Do not pool cores or rounds to conceal exceptions. Within-process confidence
intervals cannot establish repeatability across independent processes.

| Consumer | Observation across the three rounds |
| --- | --- |
| Binary PBS | u64 RustFFT improves on both cores every round. TfheFFT also favors F1, subject to the plan mismatch above. u32 RustFFT has one nearly neutral exception. |
| Classic CBS / RustFFT | All six paired means and medians improve. |
| Ternary, sparse PBS, factorized MVB | Mixed or near-neutral exceptions remain; CPU 8 sparse PBS starts at +4.53% mean, then improves twice. |
| Sparse CBS / TfheFFT | CPU 8 mean changes: +6.33%, +3.97%, −0.43%; median changes: +6.36%, +4.48%, −0.51%. All paired plans match. CPU 4 medians are nearly neutral. |

The positive evidence remains useful, but sparse CBS uncertainty prevents global
acceptance. No CPU-, word- or workload-specific dispatch was added to preserve
favorable cases. Reconsideration needs a concrete explanation and better control
of process variability, rather than repeated sampling until a favorable result.

## Cost and validation

For C=k+1 components and L decomposition levels, both variants retain
`O(CL N log N + C²L N)` work and `O(CN)` scratch. F1 removes an `O(CN)` clearing
pass and the first product's accumulator read, while introducing private
initialization state. It adds no buffer, public API, key material or setup step.
Both versions allocate zero times during preflight evaluation. The complete
benchmark's `.text` shrinks by 928 B (0.020%); that does not establish a stack or
cache benefit. RSS/setup/drop observations are not exact heap measurements.

Both versions passed untimed pre/post consumer checks. These historical checks
are not current validation or a DFR estimate. No arithmetic change was retained.

Not measured: all parameter/engine/operation combinations, rotating input pools,
concurrent requests, NTRU/high-precision LUT, Primus SIMD performance, exact peak
heap or tail latency. F1 only touched GGSW Fourier kernels.
