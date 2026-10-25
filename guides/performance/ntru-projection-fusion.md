# NTRU projection fusion

[Performance guide](README.md) · [NTT contract](../../crates/primus_ntru/src/scheme_switch/projection.rs) · [Fourier contract](../../crates/primus_tfhe_ntru_fourier/src/circuit_bootstrap/key.rs)

`CbsConfig.projection` selects the NGSW-only algorithm; the independent
[high-precision LUT library](../../../primus_high_prec_lut/README.md) uses
`HighPrecLutConfig.one_hot.projection`. The enum default is `Separate`; NTRU NTT
performance presets explicitly select `PairedTrace`. Fourier supports `Separate`
and opt-in `FusedLastStage`/`PairedTrace` with split trace/SS. Current NTT and
Fourier [LUT presets](../../../primus_high_prec_lut/guides/performance/ntru-lut-presets.md) explicitly select PairedTrace; historical names and gadgets
below differ from those request-specific presets. The strategy table describes
NTT; [Fourier results](#fourier-split-terminal-fusion) are separate. NLEV-only and dual outputs retain separate trace/SS.
The [support matrix](../development/bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support) distinguishes stage precision from projection strategy. See the [configuration example](../../crates/primus_tfhe_ntru_ntt/README.md#parameters-and-representation).

For current choices, read the [NTT strategy comparison](#current-strategy-comparison),
[Fourier paired trace](#fourier-paired-trace-production-revalidation) and
[one-hot sharing](#fourier-pairedtrace-one-hot-first-pair-sharing). The binary negative result is a separate historical baseline.

## Current strategy comparison

Measured 2026-10-18 at `f44a85029bb294456f6e02c36f7233dd265bde7c`.
One request is **one selector's complete trace＋SS**, including coefficient shifts,
all prefix blocks, modular normalization and all output rows (LowPrec two,
HighPrec one). BR, selector rotation, CMux, LWE return and setup are excluded.
This is not a complete CBS or LUT speedup claim.

u64, N=4096, Q=1125899906826241, sigma_f=sigma_g=1. Trace/SS/output bases
`(L,log2B)` are `(6,7)/(6,8)/(2,10)` for LowPrec and
`(15,3)/(6,8)/(1,17)` for HighPrec. The fixed classic-BR input is shared across
versions; the full numerical config is in the [metadata](data/ntru-projection-strategies.json).
Three rounds per CPU/profile/version, 30 samples, 1s warmup and 3s target;
rotating order, Ryzen 9 9955HX3D CPU4/8, Rust 1.98.1, repository native flags,
`--no-default-features --features ntt`. No frequency locking (`amd-pstate-epp`,
`powersave`); no concurrent experiments or compilation from this task.

Time entries are **LowPrec / HighPrec ms**, medians of three process means.
Key heap and full workspace entries likewise list **LowPrec / HighPrec**.
Heap is requested storage, not RSS; full workspace includes scratch, projected
rows and external-product scratch, but not keys or the rest of an evaluator.

| Strategy | CPU4 ms | CPU8 ms | Key heap MiB | Scratch KiB | Full workspace KiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| `Separate` | 0.6769 / 0.7250 | 0.6483 / 0.6990 | 2.802 / 6.179 | 64 | 228 / 196 |
| `FusedLastStage` | 0.6452 / 0.6849 | 0.6247 / 0.6556 | 3.005 / 6.382 | 64 | 228 / 196 |
| `FusedLastThreeStages` | 0.6118 / 0.6055 | 0.5866 / 0.5834 | 4.224 / 7.602 | 256 | 420 / 388 |
| `PairedTrace` | 0.4782 / 0.4701 | 0.4564 / 0.4490 | 6.459 / 14.055 | 160 | 324 / 292 |

`Separate` adds no fusion material. `FusedLastStage` and `FusedLastThreeStages`
keep a binary prefix and fuse one or three terminal layers with SS. At N4096,
`PairedTrace` uses five paired blocks followed by R4＋SS; each pair shares
its decomposition/NTT across three prepermuted branches. Exact schedules,
phase residuals and scratch lengths for other N belong to the linked rustdoc.

Keep `Separate` as the baseline/default. Against it, same-round median time
reductions are 3.75–6.38% for last-stage fusion, 9.23–16.64% for last-three fusion,
and **29.42–35.76% for PairedTrace**. Every paired round agrees in direction;
all pass the predeclared 3% median threshold. Last-stage fusion adds about
0.203 MiB of key data without increasing workspace. Last-three fusion needs
less key storage than PairedTrace, but **96 KiB more workspace**.
PairedTrace remains the explicit NTT performance choice when its additional
3.657/7.876 MiB shared-key heap and 96 KiB workspace over Separate are acceptable.
There is no automatic profile-dependent switching.

Key inline size is 440 B. Construction peaks, complete CBS/one-hot/LUT workspace
sizes and per-process means/95% CIs are in the metadata. Online allocation checks
passed; concurrent cache pressure was not measured. Fusion changes residuals,
correlated key errors and secret-dependent material: this is not evidence of
smaller noise or certified security/DFR. Changing strategy needs a new budget.

The frozen old Paired baseline includes base `f8f43aa0a4298955bdb400f17e6617a8ee3298b5`
**plus** patch SHA256 `62f83c5b36c4fbaa8cb25b6a896754b17e85bd92ceeca901b21498a1caf43002`.
The base commit alone is fixed R8, not the old Paired implementation.
New/old Paired median time changes (Low4/Low8/High4/High8) are
**+0.56% / +0.71% / +0.48% / −0.15%**. Three groups show a small slowdown;
no group reaches the 3% regression threshold. This does not establish zero overhead.

All 60 timing processes and [1,800 raw samples](data/ntru-projection-strategies.csv)
are retained, including outliers. The metadata stores every round and its CI,
paired ratios, execution order, source/lock/ELF hashes and memory figures.
Untimed fixture and consumer checks matched old/current Paired outputs and
observed zero online allocations. These finite samples are not DFR trials.
Published samples identify this measurement but do not constitute a standalone
reproducible stage benchmark; temporary harnesses/vectors are not maintained. Production contains no measurement-only API.

## Historical binary complete-request gate

Binary terminal fusion at baseline `7c92a0b7` did **not** meet its complete-request
performance gate. Two reversed rounds on CPU4/8, 20 samples/1s/4s, measured classic
M16/d3/c4 or c6/o4 LUTs including LWE return. CPU4 changes ranged −0.90% to+2.50%,
CPU8 −5.48% to+1.25%; some cases reversed direction. It was retained as an optional
algorithm, not a universal full-request speedup. The extra binary key/scratch
cost is historical and does not describe PairedTrace.
[All raw samples](data/ntru-projection-fusion.csv) and
[metadata](data/ntru-projection-fusion.json) remain. Use elapsed_ns/iterations;
onehot means 15 nonzero selectors, not 15 independent requests.
Earlier fixed-R8/paired prototype chronology is retired to Git. Current strategy
tradeoffs are measured directly above; do not add their percentages across baselines.

## Fourier split terminal fusion

Measured 2026-10-19, candidate based on `64ef5a150ae36578b273b530015ed092ec8fe6be`;
[metadata](data/fourier-fused-last-stage.json) identifies the exact candidate and
measurement patches, toolchain, parameters and ELF hashes. The linked data is not a standalone replay
archive; public benchmarks do not expose isolated projection.
[Process estimates and CIs](data/fourier-fused-last-stage.csv) preserve all rounds.

Native64 N4096, split40 at BR/trace/SS, f/g sigma1.5. Input LWE n1024/h128,
q=2^52, sigma3.2×2^28; KS (L,log2B)=(9,2). Low BR/trace/SS/output gadgets are
(3,16)/(5,11)/(5,11)/(1,19); High uses (4,13)/(4,13)/(4,14)/(1,20).
The fused terminal uses the SS basis, including High's b14 rather than trace's b13.

One measured projection request contains 15 real BR selector inputs and complete
trace＋SS, including ordinary output FFT, excluding BR and selector rotation.
Three rounds of neighboring modes, reversed order in round two, 20 samples,
0.3s warmup, 1.2s target, CPU4/8, unlocked frequency. Both modes use one ELF;
all 24 input pairs match, and all TFHE-FFT plans were automatically chosen
Dif8,512. Times below are medians of process means in ms (Low / High).

| CPU | Engine | Separate | FusedLastStage | Reduction |
|---|---|---:|---:|---:|
| 4 | rustfft | 6.3222 / 5.4368 | 5.9946 / 5.1414 | 5.18% / 5.43% |
| 4 | tfhe-fft | 4.6605 / 3.9873 | 4.4789 / 3.8642 | 3.90% / 3.09% |
| 8 | rustfft | 5.9442 / 5.0979 | 5.6304 / 4.8462 | 5.28% / 4.94% |
| 8 | tfhe-fft | 4.4297 / 3.8205 | 4.2430 / 3.6368 | 4.21% / 4.81% |

Every projection pair improved, but whole-consumer median reductions ranged
from −0.23% to +1.97% for one-hot, −0.37% to +0.71% for CBS, and −0.21% to
+1.06% for c4/o4/d3/M16 LUT. Individual rounds can reverse sign; the CSV retains
all adverse samples. This supports an optional projection strategy, not a
universal end-to-end speedup or a changed default.

Fused adds Low/High 352.117/288.094 KiB of cross material and 64 KiB of branch
scratch per evaluator. It borrows the existing SSK and keeps the complete trace
for NLEV/dual output. Separate allocates none of this extra storage. Parameters,
secret/BSK/trace/SSK and independent input seed match; the additional cross key
advances the RNG before downstream return-key generation. Fusion changes
floor/decomposition/key-noise terms; consumer success is not a security or DFR
certificate. See the [native phase contract](../development/bootstrapping-contracts.md).

## Fourier paired trace (production revalidation)

Measured 2026-10-19, based on `6702a304`; [metadata](data/fourier-paired-trace.json) identifies the candidate, measurement overlay, source/ELF hashes and parameters. [All process estimates and CIs](data/fourier-paired-trace.csv) include adverse rounds. The preceding FusedLastStage results remain historical evidence.

The N4096 profiles are the same as above. Three rounds on CPU4/8 use automatic FFT plans, the same table/base keys/BR input within each process, and reversed mode order in round two. Each Criterion iteration measures one complete workload; 20 samples, 0.2s warmup and 0.8s target. No concurrent build/test from this task. Frequency is not locked. The temporary fixture holds maximum scratch and an extra R2 cross clone; production owns only the selected strategy.

The following times are medians of process means, in ms (Low / High), for **15 selectors’ complete trace＋SS**, including ordinary output FFT but excluding BR/rotations. Reductions are medians of within-round ratios against FusedLastStage.

| CPU | Engine | FusedLastStage | PairedTrace | Reduction |
|---|---|---:|---:|---:|
| 4 | rustfft | 6.0161 / 5.1761 | 4.7420 / 4.0916 | 21.10% / 21.09% |
| 4 | tfhe-fft | 4.4522 / 3.8330 | 3.9480 / 3.4052 | 11.24% / 11.18% |
| 8 | rustfft | 5.6679 / 4.8821 | 4.4869 / 3.8703 | 20.98% / 21.04% |
| 8 | tfhe-fft | 4.2444 / 3.6429 | 3.7443 / 3.1961 | 11.80% / 12.28% |

For N4096, complete one-hot median reductions versus R2 span **2.16–5.27%** with RustFFT and **1.03–1.77%** with TFHE-FFT. Individual rounds can regress (CPU4 TFHE-FFT High: −3.36% once, then +1.62%/+1.39%); no samples were removed. These are measured projection/one-hot workloads, not a claimed full LUT speedup.

N2048 changes only ring length as an odd-layer R8 diagnostic, not a security preset. Projection improves 17.05–18.58% with RustFFT and 2.39–3.42% with TFHE-FFT. Complete one-hot medians range +1.24–3.44% and **−0.48% to +0.17%**, respectively. N2048/TFHE-FFT is not a performance recommendation. At this measurement, default and Fourier presets stayed Separate; current LUT presets explicitly select PairedTrace.

| N | Added key vs R2, Low / High (MiB) | Private workspace Separate / R2 / Paired (KiB) |
|---|---:|---:|
| 4096 | 5.85 / 4.78 | 96 / 160 / 288 |
| 2048 | 3.10 / 2.53 | 48 / 80 / 272 |

Payload counts include limb spectra, maps and basis arrays, excluding Vec/enum headers, allocator overhead, shared BR/FFT/EP/split, and key-generation peak/RSS. Paired keeps full binary trace for NLEV/dual, adds three pre-permuted gadgets per pair and R−1 terminal gadgets, and borrows SSK for identity. All blocks share one branch buffer; there is no production R2 duplicate.

Integer oracles and complete CBS/one-hot/LUT consumers passed, including odd/even
trace depth and NLEV/dual routes; measured online allocations were zero. This does
not certify native integer-lift tails, shared-key covariance, security or DFR;
see the [phase contract](../development/bootstrapping-contracts.md).

## Fourier PairedTrace one-hot first-pair sharing

Measured 2026-10-19 against `590b3521`; [metadata](data/fourier-one-hot-sharing.json) identifies the production source snapshot, public-API driver and two independent ELF files. [Process measurements](data/fourier-one-hot-sharing.csv) retain every round, including regressions. No measurement-only production API was added; the linked compact evidence is not a standalone replay archive.

The N4096 Low/High parameters are unchanged from the Fourier sections above, with PairedTrace selected explicitly. Three AB/BA/AB rounds on CPU4/8, automatic FFT planning, three warmups and 20 samples per complete request. All TFHE-FFT tables selected Dif8,512. Each sample measures one CBS, full 16-selector one-hot, 15-selector nonzero one-hot, or c4/d3/M16/o4 LUT including LWE return. Frequency was unlocked; no build/test ran concurrently.

The table shows median **within-round time reductions**, positive for faster. These ratios are not derived from separately pooled median times.

| CPU | FFT | Profile | Full one-hot | Nonzero one-hot | Complete LUT | Ordinary CBS control |
|---|---|---|---:|---:|---:|---:|
| 4 | rustfft | low | +2.81% | +2.94% | -0.48% | -0.49% |
| 4 | rustfft | high | +1.66% | +1.37% | +0.92% | -0.28% |
| 4 | tfhe-fft | low | +2.25% | +2.52% | +1.61% | -0.06% |
| 4 | tfhe-fft | high | -0.36% | +1.60% | +1.84% | -0.46% |
| 8 | rustfft | low | +2.34% | +2.34% | +1.22% | -0.03% |
| 8 | rustfft | high | +1.90% | +1.75% | +1.31% | +0.40% |
| 8 | tfhe-fft | low | +1.72% | +2.07% | +3.72% | +0.12% |
| 8 | tfhe-fft | high | +1.91% | +1.91% | +1.66% | -0.11% |

Nonzero one-hot improves in all measured cells. Full one-hot and complete LUT are not uniformly faster: CPU4/TFHE-FFT High full one-hot rounds are −6.29%, +1.50%, −0.36%, with long-tail samples retained; CPU4/RustFFT Low LUT rounds are −1.18%, −0.48%, +1.78%. Do not infer a general LUT speedup or attribute these variations to a particular hardware cause. A separate fixed follow-up is recorded below.

The cache holds normalized input and three completed cross products, rotated
separately per target. Shared products correlate target errors; the signed native
remainder and independent branch rounding are specified in the [projection contract](../../crates/primus_tfhe_ntru_fourier/src/circuit_bootstrap/key.rs).
The enum default remained Separate. This measurement did not change presets; current LUT presets now explicitly select PairedTrace.

At u64/N4096, measured retained heap grows by exactly **128 KiB** for a one-hot evaluator and for a LUT evaluator; their inline sizes grow by 16 bytes. Keys and ordinary CBS storage do not grow. This cache is allocated at one-hot construction even if a caller later requests only NLEV/dual. Single-target, NLEV/dual and ordinary CBS retain the original schedule. Earlier per-evaluator projection-buffer figures remain valid; add this cache only for one-hot ownership. Counts exclude allocator metadata, RSS and key-generation peak.

All formal and follow-up processes passed untimed phase/consumer checks with zero
online allocations, including dual and single-target fallback. This finite
validation does not certify security, correlated tails or a failure probability.

A fixed follow-up used the **same two ELF files**, CPU4, three AB/BA/AB rounds and 80 samples per workload, without replacing formal results. TFHE-FFT High full one-hot improved 1.64% / 1.76% / 1.81%; RustFFT Low LUT improved 1.85% / 2.41% / 0.55%. TFHE-FFT High follow-up LUT still has a −0.04% round. The CSV keeps the two datasets distinct. This supports retaining the selective one-hot schedule, not promising a universal LUT speedup.
