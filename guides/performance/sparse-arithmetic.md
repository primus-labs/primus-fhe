# Sparse coefficient arithmetic

[Performance guide](README.md) · [Current benchmark commands](../development/testing.md#tfhe-benchmarks) · [Layout and batching](sparse-layout-and-batching.md)

The retained kernels reduce coefficient-aggregation work without changing the
canonical aggregate, transforms, external products or ciphertext noise. The
arithmetic contracts below describe the current selection rules. The pair/group
and Fourier reassessments were measured on 2026-10-06
at source `09e5f1b8`; the GLWE four-source confirmation below uses `44d01d7a`
plus only the private aggregation change. Their percentages must not be added to
results against earlier baselines or treated as parameter recommendations.

## Retained arithmetic and fallback

| Path | Selection and fallback |
| --- | --- |
| NTRU NTT | u64 uses bounded lazy pairs; u32 uses canonical pairs. An odd selector uses the corresponding single update. |
| GLWE NTT | u64 fuses four sources per traversal within a whole-bucket group when at least four selectors fit the modulus headroom; otherwise it uses bounded lazy pairs. u32 uses four-source fusion within batches of up to 28 sources, sized by modulus headroom; insufficient headroom or buckets shorter than four retain canonical single updates. |
| GLWE NTT group reduction | u64 with AVX-512F/DQ selects the vector-friendly reciprocal kernel; other cases use Barrett reduction. |
| NTRU Fourier | u64 uses groups of four, then pairs/single for the tail; u32 uses pairs/single throughout. |

All paths copy the bucket dummy before accumulating. Empty buckets, zero
exponents and encrypted zero selectors keep their existing meaning; no selector
is skipped. Complete polynomial lengths, valid exponents in `[0,2N)` and matching
control layouts are established by the keys and workspace. Source-key reads are
unchanged. The kernels reuse the existing aggregate, with no extra retained heap,
key field or public configuration.

### NTRU paired coefficient aggregation

Two adjacent selectors share one aggregate traversal, preserving source order;
an odd tail uses a single update. This applies to both NTRU backends, including
the pair fallback of the Fourier four-way path. It preserves first-bucket NLEV
lifting and later NGSW consumption through the same external-product operation.
The [NTT](../../crates/primus_tfhe_ntru_ntt/src/sparse/blind_rotation.rs) and
[Fourier](../../crates/primus_tfhe_ntru_fourier/src/sparse/blind_rotation.rs)
traversals use `NlevIter` and borrowed views. Fusing selector updates does not
change the number of transforms or external products.

### Bounded lazy NTT pair

The [shared polynomial kernels](../../crates/primus_poly/src/monomial/lazy.rs)
accept canonical sources `a,b` in `[0,q)` and an initialized accumulator in
`[0,2q)`. For each interval of constant rotation signs, a pair computes one of:

```text
acc + a + b
acc + a + q - b
acc + q - a + b
acc + 2q - a - b
```

The bias prevents underflow. Intermediates stay below `4q`, representable under
Barrett's `q < 2^(BITS-2)` bound. One conditional subtraction of `2q` restores
`[0,2q)`; a single tail stays below `3q` and uses the same correction. At bucket
completion, one `reduce_once_slice_assign` restores `[0,q)` before the ordinary
NTT. This does not widen the NTT input contract or introduce full Barrett
reduction inside the pair loop. TFHE selects this path for u64 only.

### Whole-bucket GLWE NTT accumulation

For `m` canonical sources, add `m*q` to the canonical dummy accumulator, then
apply rotated contributions in `[-(q-1),q-1]`. Every prefix remains nonnegative
and below `(2m+1)*q`. The conservative capacity is:

```text
max_group_len = floor((floor(T::MAX / q) - 1) / 2)
```

The [aggregation helper](../../crates/primus_tfhe_glwe_ntt/src/sparse/aggregation.rs)
computes this by dividing first and caps it at `usize::MAX`. The u64 dispatcher
requires `4 <= m <= max_group_len`, so the whole bucket must fit.
At Q=1125899906826241, capacity is 8191.

Four sources share each aggregate traversal; the remainder uses the existing
native pair/single kernels. The four rotation wrap points divide a polynomial
into at most five contiguous intervals. A 4-bit sign mask selects the arithmetic
outside each coefficient loop, preserving source order and reducing aggregate
loads/stores without reducing source-key reads. The bound prevents actual word
wrapping; each tile is then fully reduced before NTT. Tiles contain complete
polynomials, targeting 16 KiB and retaining at least one polynomial. Short or over-capacity u64 buckets use bounded pairs instead of
multiple groups and repeated full reductions. Selection depends only on public
bucket size and modulus. NTRU does not use whole-bucket grouping.

### GLWE four-source confirmation (2026-10-15)

The complete `pbs/glwe/ntt/sparse_fixed/u64` request was compared at `44d01d7a`
with and without the four-source substitution. Both use n728/h32/N1024/k1,
q=Q=1125899906826241, r3/B64, BR/KS b8/L6, BR→KS, padded t32 input,
f(m)=(3m+1) mod 16, key seed42 and input seed4242. Setup and returned-message
checks are outside timing. The measurement-time uninstrumented benchmark and default
Criterion sampling mode were retained.

On the Ryzen 9 9955HX3D with rustc 1.98.1 / LLVM 22.1.8 and `target-cpu=native`,
each CPU used three separate process pairs in AB/BA/AB order: 30 samples,
1 s warmup, 5 s measurement target, no concurrent measurements or replacement
rounds. No portable SIMD feature was enabled. Values below are medians of three
process means; the reduction is the median of paired ratios.

| CPU | Pairs (ms) | Four sources (ms) | Median paired reduction |
| --- | ---: | ---: | ---: |
| 4 | 14.418 | 12.541 | 13.02% |
| 8 | 15.319 | 14.130 | 8.26% |

All six paired mean ratios and their conservative CI upper ratios are below 1.
The [per-process means and intervals](data/sparse-ntt-four-source.csv) retain all
rounds. Frequency/background activity was not controlled; this is not an ISA-wide
performance guarantee. An earlier experiment had one CPU8 PBS interval crossing
1 despite improved means throughout; this confirmation does not erase that
result or merge its samples. CBS and other parameters were not retimed here.

The PBS binary `.text` grows from 2,793,894 to 2,811,542 bytes (+0.63%). The helper
adds fixed-size stack arrays and 16 sign specializations, without retained heap,
key/workspace expansion, new public API or changes to transforms/external products.
Independent integer tests cover modulus headroom, wrap signs and tails; u64
PBS/CBS workflows and the full sparse two-stage smoke also pass.

### u32 reduction batches independent of four-source fusion (2026-10-15)

The current u32 path computes `batch_len = min(max_group_len, 28) & !3` once
before the bucket/tile loops. Every batch adds the existing `m*q` bias, consumes
groups of four and a pair/single tail, then reduces to `[0,q)`. The same
`(2m+1)*q` proof applies independently to every batch. A zero batch length or
a bucket shorter than four retains canonical single updates. At Q1=67104769,
capacity is 31 and the batch length is 28; no special-modulus reducer or relaxed
NTT input range is used. u64 whole-bucket accumulation is unchanged.

This comparison starts at `dd2df1a1` and changes only that batching policy and
its private loop placement. The [two-stage benchmark](../../../primus_omr/benches/sparse_two_stage.rs)
uses independent n1024/h64 secrets, r3/B67, real convolution public-key clues,
four first-stage BRs summed before one ring KS/extraction/MS, then one second-stage
BR and reverse trace. Q1=67104769/N1=1024, Q2=1125899906826241/N2=2048;
BR gadgets are b4/L4 and b8/L5, KS b2/L6, trace b10/L4. Messages and noise
parameters are unchanged: full t64 → signed sum at t18 → RLWE t257.
Stage-specific rows below refer to the historical source; the current OMR target
measures only the complete detection request.

Ryzen 9 9955HX3D, rustc 1.98.1 / LLVM 22.1.8, repository `target-cpu=native`,
default features. CPU4 (96 MiB L3) and CPU8 (32 MiB L3) each ran three independent
process pairs in AB/BA/AB order, sequentially, with 20 Flat samples, 1 s warmup
and a 3 s target. No rounds were replaced. Times are medians of process means;
reductions are medians of paired ratios. [All process means and intervals](data/glwe-u32-batch28.csv)
are retained.

| CPU | Workload | Four-source batches (ms) | Up to 28 sources (ms) | Paired reduction |
| --- | --- | ---: | ---: | ---: |
| 4 | One first-stage PBS including return | 7.063 | 6.020 | 14.75% |
| 4 | Complete request | 59.407 | 55.481 | 6.61% |
| 8 | One first-stage PBS including return | 7.688 | 6.683 | 13.07% |
| 8 | Complete request | 59.745 | 55.600 | 6.80% |

Every complete-request pair improves (CPU4: 5.27%–6.92%; CPU8: 6.57%–7.42%).
The unchanged second stage has median paired changes of +0.26%/+0.84% in time;
one CPU8 pair is +7.18%, retained in the data. Frequency and background activity
were not isolated, so no improvement is attributed to that stage.

The frozen first key has 3072 selectors in 67 buckets of lengths 35–61. Reduction
batches per BR drop from 795 to 139, each applied across the same aggregate tiles.
All source reads, transforms and external products remain. No heap allocation,
key or workspace storage is added. The sparse executable `.text` grows by 1088
bytes (+0.032%); its u32 BR stack frame grows by 48 bytes. Assembly retains AVX-512
four-source add/sub loops and Barrett batch reduction; the capacity division is
outside the bucket loop.

Integer-oracle tests cover both widths, modulus headroom, all signs, maximal
prefixes, tails and multiple tiles/batches. Classic and sparse two-stage input,
pre/post-KS, returned LWE and pre/post-trace ciphertexts are bit-for-bit identical
across both builds for real-clue and synthetic boundary fixtures. The historical validation passed. This is a fixed-parameter
arithmetic improvement, not a security/DFR certification or a performance claim
for other moduli, CPUs or CBS workloads.

### Rejected reduction specializations

Per-segment negative-count bias and special Q1=2²⁶−4095/Q2=2⁵⁰−16383
folding passed exact arithmetic checks but did not show repeatable complete-request
benefit on both CPU4/8. They add sign/tail or modulus-specific contracts without
reducing key reads or storage; none is retained. Detailed retired samples are
recoverable in Git. This does not establish that folding is intrinsically slower.

### Compact sparse bucket reduction

Within the GLWE group path, let `B=2^64`, `x` be any u64 value and
`mu=floor(B/q)`, taken from the high limb of the Barrett reciprocal. The estimate
`floor(x*mu/B)` underestimates `floor(x/q)` by at most one. Computing the high
product from three 32-bit partial products, omitting the low-low product, loses
at most one more. Thus `x-estimate*q` lies in `[0,3q)`; conditional subtraction
of `2q` and then `q` produces the canonical residue.

The partial products and their middle carry sum fit u64. Since `q < 2^62`,
`3q < B`; the estimated product is at most `x`, so multiplication and subtraction
do not overflow. This reduction accepts the whole word, not only the observed
bucket range, and restores the ordinary NTT's `[0,q)` input.

The private helper checks AVX-512F/DQ outside the coefficient loop and lets LLVM
vectorize safe slice arithmetic inside the target-feature function. Unsupported
CPUs retain scalar Barrett reduction. u32, other backends and generic modulus
APIs are unaffected. These dispatch conditions matter: the recorded combined
gains below do not establish non-AVX-512 performance.

### Fourier four-way accumulation

The [NTRU Fourier helper](../../crates/primus_tfhe_ntru_fourier/src/sparse/aggregation.rs)
adds four native coefficient rotations before FFT. Four wrap points split each
polynomial into at most five intervals; a dispatch outside the coefficient loop
specializes the 16 possible sign combinations. Each coefficient loads/stores
its aggregate once and consumes all four sources in their original order.
Wrapping arithmetic is exact in `Z/(2^64)`, giving the same result as two pair
updates. No floating-point sum is reordered. A tail of 1–3 selectors uses pairs
and a possible single update; u32 retains that fallback for the whole bucket.

The cost is code size. In the saved reassessment PBS binary, the u64 aggregate
symbol grew from 7,156 to 32,601 bytes, about 25 KiB. Total `.text` grew by
23,008 bytes for PBS and 42,864 bytes for LUT; those binary-wide differences
include inlining/layout effects and are not a universal cost per instantiation.
Only fixed-size stack arrays are added. A smaller sign-mask candidate did not
match the measured benefit of specialization; it was not retained.

## Reassessment conditions

Both reassessments isolate an arithmetic substitution within `09e5f1b8`; they do
not compare whole revisions. AMD Ryzen 9 9955HX3D, rustc 1.98.1 / LLVM 22.1.8,
release and repository `target-cpu=native` were used without portable SIMD.
Fourier enabled both FFT engines; its historical LUT target also required NTT.
Logical CPU 4 belongs to the 96 MiB L3 group and CPU 8 to the 32 MiB group;
both support AVX-512F/DQ. Compare variants **within each CPU**. Frequency and
unrelated activity were not locked, and no cache or writeback cause was measured.

Each CPU/workload used four fresh processes in ABBA order, reversing A/B for
successive workloads and CPU 8. Each process used a separate Criterion directory,
30 samples, 0.5 s warmup and a 3 s measurement target. Paper and LUT workloads
used Flat sampling; diagnostic PBS/CBS/one-hot kept their ordinary mode. The
Fourier confirmation used 50 samples, 1 s warmup and an 8 s target.

One iteration was one complete request using fixed inputs and reusable buffers.
Key generation, LUT compilation, encryption, allocation and validation were
outside timing. PBS included its return to LWE; paper NAND also included affine
preprocessing and q↔Q conversion. CBS/one-hot timed gadget generation with CMux
validation **outside** timing, unlike later CBS/one-hot consumer benchmarks. Stage
probes were not included or subtracted from complete-request times.

### Historical workload parameters

These are arithmetic diagnostics, not security/DFR recommendations. In this
table `q` is the external modulus and `Q` the ring modulus; `r/B` gives replica
and bucket counts. `b/L` means decomposition base log and level count.

| Workload | n / h / N | q / Q | r / B | BR b/L |
| --- | --- | --- | --- | --- |
| GLWE STD128 NAND r3 | 1024 / 43 / 1024 | 512 / 268369921 | 3 / 46 | 7/4 |
| GLWE STD128 NAND r2 | same | same | 2 / 86 | 7/3 |
| GLWE padded function r3 | 2048 / 70 / 2048 | 4096 / 18014398509404161 | 3 / 73 | 27/2 |
| GLWE padded function r2 | same | same | 2 / 140 | 27/1 |
| GLWE u64 diagnostic | 728 / 32 / 1024 | Q / 1125899906826241 | 3 / 64 | 8/6 |
| NTRU Fourier u64 PBS/CBS/one-hot | 728 / 32 / 1024 | 2^24 / 2^64 | 3 / 64 | 8/8 |
| NTRU Fourier u64 LUT | 800 / 32 / 1024 | 2^24 / 2^64 | 3 / 64 | 8/8 |

GLWE has k=1. Paper ring KS uses b7/L4 for NAND and b5/L10 for the function;
r2 and r3 are distinct parameter sets, each held fixed across its arithmetic
comparison. The diagnostic PBS/CBS message moduli are 8/4; one-hot uses t8/M4
and emits three nonzero controls. Historical diagnostic bases/noise are recorded
in Git at `4e2639ce`; all other
return, trace and scheme-switch settings remain fixed within each comparison.

The LUT workloads have eight two-bit input and output chunks, d=5, and return
all eight output chunks. One evaluates `x*x+3*x+7 mod 2^16`; the other uses a
seed-42 dense mapping. Both variants retain the same two-input blind-rotation
traversal and historical selection/return implementation. These are not the
M16/d3/N4096 complete-tree benchmarks; the old LUT percentages do
not validate performance of the new workload.

## Grouped NTT reassessment

**Decision: retain GLWE u64 grouping with compact reduction within its bounds.**
The comparison disables only group dispatch and its private module in the pair
variant, keeping bounded lazy pairs followed by one canonicalization before NTT.
Both variants retain the same tiles, dummies, source order, odd tails, keys,
transforms, external products, return path and noise. Grouping plus reduction
is measured together, not attributed separately to the two changes.

The [80 process records](data/sparse-group-pair-reassessment.csv) cover ten
workloads on both CPUs. The eight u64 target workloads improve by 5.12%–10.39%;
the unchanged u32/classic controls vary by −0.54% to +0.36%. Results average two
process means per variant; per-process 95% intervals remain in the CSV, unpooled.

Every neighboring comparison favors grouping in the eight u64 targets.
No retained heap or key growth is needed. Same-key untimed input/output captures
matched. This supports a local arithmetic choice, not security/DFR or another ISA.

## Fourier four-way reassessment

**Decision: retain the private NTRU Fourier u64 specialization.** The pair variant
removes only the four-control branch and helper, using the existing pair/single
loop for all selectors. Both single-input and two-input instantiations keep the
same dummies, selectors, transforms, products and returns.

The [124 process records](data/sparse-fourier-four-way-reassessment.csv) contain
112 main measurements and 12 longer confirmations. Main PBS/CBS/one-hot means
improve by 1.86%–9.38%, and historical LUT means by 3.44%–5.60%. Results use
the same two-process mean convention as the NTT comparison.

Every neighboring u64 target favored four-way. The unchanged CPU8 TFHE-FFT/u32
control appeared 3.95% faster in the main matrix, narrowing to 0.21% with longer
reversed-order sampling. CPU8 RustFFT one-hot main gain was only 1.86%; a later
7.44% result had an unstable pair baseline and does not replace it.
All main and confirmation rows remain. Complete ciphertexts matched within each
engine; floating-point order is unchanged because aggregation is exact torus arithmetic.
GLWE Fourier/u32 four-way and portable-SIMD performance were not measured.

## Independent u64 BR inputs sharing key tiles

GLWE NTT's batch workspace serves independent u64 inputs in groups of four,
then two and one for short tails. It reuses the same 16 KiB source tiles,
rotation kernels, per-input reduction bounds, canonical NTT and external products.
Each lane owns its aggregate and scratch; single-input BR retains its original
kernel. Keys and transform tables are shared, while each input retains its
bucket order and arithmetic. The batch kernel is single-threaded and adds no
per-call allocation.

Application scheduling and its measurements belong to the independent
[OMR guide](../../../primus_omr/guides/performance/omr-scheduling.md):
[four-way detection](../../../primus_omr/guides/performance/omr-scheduling.md#four-way-sparse-detection),
[parallel detection](../../../primus_omr/guides/performance/omr-scheduling.md#parallel-detection),
[bounded retrieval](../../../primus_omr/guides/performance/omr-scheduling.md#bounded-complete-retrieval)
and [parallel retrieval](../../../primus_omr/guides/performance/omr-scheduling.md#parallel-complete-retrieval).
Those reports retain the four historical datasets, measured source/ELF identities,
output-layout differences, adverse controls and allocation/RSS distinctions.
Their complete-request gains do not establish a speedup for single-input BR or
other callers of the shared kernel.

## Evidence limits

The [NTT](data/sparse-group-pair-reassessment.csv),
[Fourier](data/sparse-fourier-four-way-reassessment.csv),
[four-source](data/sparse-ntt-four-source.csv) and
[batch28](data/glwe-u32-batch28.csv) files preserve all process summaries and adverse
controls. Their units are milliseconds; compare the same CPU/workload/round.
For the first two matrices, table means average the two process means per variant;
changes are `100*(candidate/pair-1)`. Keep main and confirmation rounds separate.
The other tables explicitly use medians of paired ratios. Do not pool CI endpoints.

The historical NTRU LUT workload used a content-pruned M4/c8/d5/o8 table, not
today's complete M16 tree. Its times cannot validate current LUT performance.
The paper r2 cases change replica/bucket parameters, not arithmetic algorithms.
Detailed old fixtures and retired experiments are recoverable in Git at `bbf235ed`.
These CSVs identify historical process statistics, not standalone replay bundles.
Current commands are in the [benchmark guide](../development/testing.md#tfhe-benchmarks).
