# Sparse blind rotation: arithmetic and scheduling

[Performance guide](README.md) · [Current commands](../development/testing.md#tfhe-benchmarks)

Sparse BR retains every encrypted-zero selector and bucket dummy. The changes
below preserve the canonical coefficient aggregate, per-input order, transforms,
external products and noise. They reduce aggregate traffic or reuse public key
tiles; they do not reduce source-key reads or prove a cache/bandwidth mechanism.

## Current dispatch and ownership

| Path | Arithmetic and fallback |
| --- | --- |
| NTRU NTT | u64 bounded lazy pairs; u32 canonical pairs; single odd tail |
| GLWE NTT u64 | Whole-bucket grouping and four-source traversals when modulus headroom fits; otherwise lazy pairs |
| GLWE NTT u32 | Four-source traversals in bounded batches of at most 28; canonical single updates when headroom/bucket size is insufficient |

All paths initialize from the dummy. Native coefficient additions are exact
wrapping arithmetic; no floating-point accumulation order changes. NTRU's first
NLEV lift and later NGSW products retain their existing roles.

The [lazy pair contract](../../crates/primus_poly/src/monomial/lazy.rs) requires
canonical sources, an aggregate in `[0,2q)` and Barrett's two spare bits. Signed
updates stay below `4q`; one correction restores `[0,2q)`. Canonicalize before
ordinary NTT. This optimization does **not** relax its input range to 2q/4q.

For m canonical sources, a canonical dummy plus bias `m*q` keeps every prefix
nonnegative and below `(2m+1)*q`. The conservative capacity is
`floor((floor(T::MAX/q)-1)/2)`. u64 groups only a whole bucket that fits; u32
uses `min(capacity,28)&!3` per batch. At Q50 capacity is 8191; at Q1=67104769
it is 31, giving u32 batches of 28. Each completed tile/batch is fully reduced.
The [owning helper](../../crates/primus_tfhe_glwe_ntt/src/sparse/aggregation.rs)
contains the range and reciprocal-reduction proofs: AVX-512F/DQ u64 uses the
bounded high-product estimate and two corrections; other CPUs retain Barrett.

Keep 16 KiB tiles of complete polynomials, at least one polynomial. u64
multi-tile buckets precompute four-rotation descriptors once and reuse them;
u32 and single-tile layouts compute addresses directly. Each lane reserves at
most `floor(n/4)` descriptors and refreshes only the active prefix. Allocation
occurs at workspace construction, not online. Historical x86_64 descriptors
were 280 B each; this is not a stable ABI promise.

GLWE's [batch workspace](../../crates/primus_tfhe_glwe_ntt/src/sparse/blind_rotation.rs)
uses four independent lanes, then two/one for short tails. Keys/tables are shared,
each lane owns exponents, aggregate and product scratch. Single-input BR keeps
its own kernel; batch speedups cannot be multiplied into single-input timings.
NTRU one-hot sparse inputs have a separate two-input path with single tails;
its classic path remains single. See [the NTT pair implementation](../../crates/primus_tfhe_ntru_ntt/src/circuit_bootstrap/one_hot/pair.rs).
No threads or benchmark-only API are part of these kernels.

## Retained arithmetic evidence

These are historical fixed-workload comparisons, not parameter recommendations.
Ryzen9 9955HX3D CPU4/8 are two cores of one machine, with 96/32 MiB L3.
Rust1.98.1/LLVM22.1.8, release/native, no nightly portable SIMD; frequency and
background activity were not locked. Compare within one CPU/workload/round.
Setup, keygen, encryption, allocation and checks were outside timing.

| Comparison / source | Complete-request observation | Evidence |
| --- | --- | --- |
| GLWE u64 grouping＋reciprocal vs pairs, `09e5f1b8` substitution | Eight u64 targets improve 5.12–10.39%; unchanged u32/classic controls −0.54…+0.36% | [80 process records](data/sparse-group-pair-reassessment.csv) |
| GLWE NTT four-source vs pair grouping, `44d01d7a` substitution | CPU4: 14.418→12.541 ms, paired reduction 13.02%; CPU8: 15.319→14.130 ms, 8.26% | [All six process pairs](data/sparse-ntt-four-source.csv) |
| u32 batches 4→28, `dd2df1a1` substitution | OMR detection CPU4: 59.407→55.481 ms, 6.61%; CPU8: 59.745→55.600 ms, 6.80% | [All process/control records](data/glwe-u32-batch28.csv) |

The grouping-versus-pairs matrix averages two process means per variant (ABBA);
the last two show medians of process means and medians of within-round reductions
(three AB/BA/AB pairs). Those statistics cannot be interchanged or pooled.
The u32 unchanged second stage includes a +7.18% pair; no benefit is attributed
to it. Code growth was +0.63% for the four-source PBS binary and 1088 B for the
u32 batching binary; fixed stack specialization adds no retained key/heap.

The historical geometry below identifies the measured cases; full fixtures are
bound to their recorded source, not today's presets. `b/L` is base log/levels.

| Workload | n/h/N; q/Q | Replicas/buckets; BR b/L; return |
| --- | --- | --- |
| GLWE paper NAND | 1024/43/1024; 512/268369921 | r3/B46: 7/4; r2/B86: 7/3; ring KS7/4 |
| GLWE paper function | 2048/70/2048; 4096/18014398509404161 | r3/B73: 27/2; r2/B140: 27/1; ring KS5/10 |
| GLWE diagnostic/four-source | 728/32/1024; q=Q=1125899906826241 | r3/B64; BR/KS8/6; PBS return to LWE |
| u32 batching/OMR detection | independent n1024/h64 secrets; N1=1024/Q1=67104769, N2=2048/Q2=1125899906826241 | r3/B67; BR1 4/4, BR2 8/5; KS2/6, reverse trace10/4 |

Four-source confirmation uses padded t32 and `f(m)=(3m+1) mod16`, seed42/4242.
The u32 comparison uses real convolution clues: four BR1 outputs summed at Q1,
one ring KS→extraction→MS, then BR2/reverse trace; full t64→signed t18→RLWE t257.
It excludes clue creation and encode/recovery. r2/r3 use different public
parameter sets and require separate security analysis.

## Batch and tile decisions

[Historical u32 batch scheduling](data/glwe-br-batch-scheduling.csv), based on
`931e3bac` plus the schedule, ran three rotating process triplets, 20 Flat samples,
1s warmup/3s target. Its complete sparse detection medians were 55.533→45.182 ms
on CPU4 and 58.039→44.018 ms on CPU8 (18.64%/24.20% paired reductions).
Four lanes added 315 KiB including caller outputs, no key copy. The former generic
lane loop slowed single-input BR; keeping its original loop is part of adoption.

Classic's seven-input schedules were rejected: CPU4 complete requests regressed
0.65–1.97%, while CPU8 improved 0.95–3.41%; the extra 148 KiB was not justified.
Its independent n512/q2048, N1=1024/Q134215681→n690/q4096→N2=2048/Q50 fixture
has different parameters from sparse and is not an equal-security comparison.
Current u64 four/two/one adoption, multiworker ownership and complete retrieval
measurements belong to [OMR scheduling](../../../primus_omr/guides/performance/omr-scheduling.md),
not this older u32 matrix.

The [u32 32 KiB experiment](data/glwe-u32-single-tile.csv) had −2.71%/+4.01%
single-input confirmation changes on CPU4/8 and neutral complete results.
[u64 32/64 KiB](data/glwe-u64-single-tile.csv) gave overlapping complete intervals.
All screens and confirmations remain; 16 KiB is retained. Older descriptor/one-lane
cleanup rounds have been superseded by the current four-lane owner and retired
to Git `c6a6fcbe`; they do not describe current batch memory.

## Rejected alternatives and limits

| Alternative | Reason not adopted |
| --- | --- |
| Negative-count bias or special Q1=2²⁶−4095/Q2=2⁵⁰−16383 folding | Correct arithmetic but no repeatable complete gain on both CPUs; more sign/modulus contracts |
| `[-p,p,-p]` expanded keys | Algorithm 2 storage trick, not Algorithm 3; triples payload without repeatable cross-profile complete gain against compact fused rotation/add |
| Level streaming, tile-major keys or NTRU coefficient tiling | Mixed complete results, extra traversal/layout/construction costs |
| GLWE trivial first bucket | Tiny local saving without repeatable complete gain |
| Old first-layer shared projection | Extra cached nodes for only K−1 automorphisms; unstable complete benefit |

Per-process intervals are not between-process confidence bounds. PBS timings
include return; historical CBS/one-hot timings above exclude CMux, which was
validated outside timing. Grouping/reduction was measured jointly, not as two
separable speedups. No results certify accepted-map security, joint key tails,
DFR, another ISA or current full-tree LUT performance. Retired data is recoverable
from Git; removed temporary harnesses/HEXL overlays are not maintained integrations.
