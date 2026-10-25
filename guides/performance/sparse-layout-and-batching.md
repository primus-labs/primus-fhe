# Sparse layout, scheduling and input batching

[Performance guide](README.md) · [Arithmetic](sparse-arithmetic.md) · [Commands](../development/testing.md#tfhe-benchmarks)

Keep compact source keys, 16 KiB aggregate tiles, opt-in GLWE NTT u32 batching,
and the NTRU paired sparse path. These schedules change temporal reuse, not
selector counts, per-input order, canonical NTT input or ciphertext noise.
No threads, measurement-only API or online allocations are introduced.

## GLWE batch scheduling

A u32 batch uses independent lanes in groups of four, then two and one. Single
inputs retain the original loop; rotation/reduction/transform/product kernels
are shared. Four-input results matched individual calls coefficient for coefficient.
In the historical comparison below, u64 batches ran sequentially with one BR
workspace. The later [u64 four/two/one-lane kernel](sparse-arithmetic.md#independent-u64-br-inputs-sharing-key-tiles)
and its independent OMR evidence are described separately.

Historical source `931e3bac` plus only the schedule change, measured 2026-10-16:
Ryzen 9 9955HX3D CPU4/8, rustc 1.98.1 / LLVM 22, native/default features.
Sparse fixture: four real convolution clues, independent n1024/h64 secrets,
r3/B67, u32 N1024/Q67104769 BR b4/L4 sigma3.19, ring KS b2/L6 sigma1633.28,
q4096/t18 return; second BR u64 N2048/Q1125899906826241 b8/L5 and normalized
reverse trace b10/L4 sigma0.849, output t257. Complete includes ring summation,
one KS/extraction/MS and second BR/trace, excludes clue creation and encode/recovery.
Three rotating process triplets, 20 Flat samples / 1s warmup / 3s target; no concurrent build.
Frequency/background activity were uncontrolled. Medians of process means:

| CPU | Sequential complete ms | Batched complete ms | Median paired reduction |
| --- | ---: | ---: | ---: |
| 4 | 55.533 | 45.182 | 18.64% |
| 8 | 58.039 | 44.018 | 24.20% |

The [full sparse/classic comparison](data/glwe-br-batch-scheduling.csv) retains
all controls. Single-input paired changes were −0.46%/−0.79%; unchanged second
stage was −0.16%/+1.06%. The original generic lane loop regressed single inputs;
restoring that loop is part of the retained design. Four lanes add 315 KiB retained
payload including caller outputs; no key copy. Single-input applications keep
ordinary scratch. This binary's `.text` grew 2.11%; heap is not RSS.

Classic seven-input scheduling was not retained. Its separate fixture used
n512/q2048, u32 N1024/Q134215681 BR b5/L4, ring KS to n690 b2/L7, q4096/t30,
then u64 N2048/Q50 BR b8/L5 and ordinary trace b4/L12, t257.
The same CSV keeps 2+2+2+1,4+1+1+1,4+2+1: CPU4 full requests regressed 0.65–1.97%,
CPU8 improved 0.95–3.41%. The extra 148 KiB and interface were not justified.
This is not an equal-security classic/sparse comparison or a batch PBS/CBS API.

## Rotation descriptors and tiles

u64 prepares four-source boundaries, offsets and signs once per bucket, reusing
them across 16 KiB tiles. Arithmetic, reads and NTT/product counts stay unchanged.
Single-tile and u32 controls bypass preparation. Multi-tile scratch reserves
floor(n/4) descriptors (280 B each on x86_64, 70 KiB at n1024), refreshing only the
active prefix; the same-layout-key contract avoids online allocation.

The [descriptor comparison](data/glwe-u64-rotation-reuse.csv) used the preceding
batch schedule as baseline, three AB/BA/AB pairs per CPU, 30 Flat samples/2s/5s,
plus 40/2s/10s follow-ups. Complete paired medians improved 1.51%/1.44%; longer
pairs improved 0.60–1.82%. Unchanged first-stage controls varied −4.22% to+1.15%.
This is a small fixed-workload result, not evidence of a cache mechanism.

The subsequent [workspace cleanup](data/glwe-sparse-rotation-cleanup.csv) removed
three inactive u64 lane workspaces (about 1.45 MiB). Longer 50/2s/10s comparisons
showed complete changes **+0.21%/+0.18%**, so keep it for bounded ownership,
not a no-regression claim. Perf measured 120 warmed complete evaluations with
100% counter running time: instructions +0.15%, cycles +1.74%/−1.71%, cache misses
+1.09%/+1.27%. Generic events do not diagnose bandwidth or a particular cache.
The CSV retains shorter adverse rounds, all 16 perf records and binary hashes.

Keep16 KiB for both widths. [u32 32KiB](data/glwe-u32-single-tile.csv) gave
−2.71%/+4.01% single-input confirmation changes on CPU4/8 and neutral complete
results. [u64 32/64KiB](data/glwe-u64-single-tile.csv) gave overlapping complete
intervals despite small stage gains. Every screen and confirmation is retained.
A temporary phase probe placed u64 aggregation at 86–87% of second BR/trace;
that timer result is not a bandwidth diagnosis or production acceptance test.

## NTRU paired sparse BR

Independent sparse LUT inputs can run in pairs; classic BR and odd tails remain
single. Each input owns aggregate/accumulator/exponents and shares sequential
transform/product scratch. See [NTT](../../crates/primus_tfhe_ntru_ntt/src/circuit_bootstrap/one_hot/pair.rs)
and [Fourier](../../crates/primus_tfhe_ntru_fourier/src/circuit_bootstrap/one_hot/pair.rs).
Additional pair payload is `(L_BR+1)*N*sizeof(T)+n*sizeof(usize)`.
Published M16 presets explicitly use **classic BR**. Old paired gains used
content-pruned M4 tables; they are not current complete-tree performance evidence.

## Rejected alternatives

| Alternative | Reason not retained |
| --- | --- |
| `[-p,p,-p]` expanded keys | Algorithm 2 storage trick, not Algorithm 3; triple key payload. Compact kernels already fuse rotation/add, so compare against those kernels. No repeatable cross-profile complete gain justified the extra layout. |
| NTRU/Fourier coefficient tiling | Mixed full-request results, no storage saving |
| GLWE trivial first bucket | About 5–7us saved against 16ms, no repeatable complete gain |
| Level streaming / tile-major keys | Mixed PBS/CBS results; extra traversal/layout contract and construction scratch |
| Old first-layer shared projection | Saved only K−1 automorphisms but added two N-coefficient nodes; complete gains unstable |

The last row is distinct from retained Fourier PairedTrace
[first-pair sharing](ntru-projection-fusion.md#fourier-pairedtrace-one-hot-first-pair-sharing).
Detailed retired experiments are in Git at `bbf235ed`; the old author/OpenFHE
HEXL overlay is not a maintained integration. A build flag alone does not prove
HEXL dispatch or comparable parameters. None of these results establishes a
universal slowdown, current security/DFR, or application-level parallel throughput.
