# NTRU projection strategies and costs

[Performance guide](README.md) · [NTT contract](../../crates/primus_ntru/src/scheme_switch/projection.rs) · [Fourier contract](../../crates/primus_tfhe_ntru_fourier/src/circuit_bootstrap/key.rs)

Configure `CbsConfig.projection` before keys/workspace construction. The default
is `Separate`; NTT performance presets explicitly use `PairedTrace`. Fourier
supports opt-in `FusedLastStage`/`PairedTrace` only with split trace and SS.
NLEV-only/dual outputs retain separate trace/SS. The [support matrix](../development/bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support)
owns precision/strategy restrictions; the [LUT presets](../../../primus_high_prec_lut/guides/performance/ntru-lut-presets.md)
select PairedTrace explicitly. Their request-specific gadgets differ from every
historical Low/High profile below; those labels are not current input-width or DFR targets.
These are projection decisions, not universal
complete-CBS/LUT speedups or noise/security certificates.

## Current strategy comparison

The 2026-10-18 NTT comparison at `f44a85029bb294456f6e02c36f7233dd265bde7c`
measured **one selector's complete trace＋SS**, all output rows, shifts and
normalization. It excluded BR, selector rotation, CMux, LWE return and setup.
N4096/u64/Q1125899906826241, sigma_f/g=1; trace/SS/output `(L,log₂B)`:
Low `(6,7)/(6,8)/(2,10)`, High `(15,3)/(6,8)/(1,17)`.

Ryzen9 9955HX3D CPU4/8, Rust1.98.1/native, NTT only; three rotating process
rounds, 30 samples/1s warmup/3s target, unlocked frequency. Times are medians of
process means, **Low / High ms**. Requested key heap and workspace exclude RSS
and allocator overhead; workspace includes scratch, projected rows and EP scratch.

| Strategy | CPU4 ms | CPU8 ms | Key heap MiB | Scratch KiB | Full workspace KiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Separate | 0.6769 / 0.7250 | 0.6483 / 0.6990 | 2.802 / 6.179 | 64 | 228 / 196 |
| FusedLastStage | 0.6452 / 0.6849 | 0.6247 / 0.6556 | 3.005 / 6.382 | 64 | 228 / 196 |
| FusedLastThreeStages | 0.6118 / 0.6055 | 0.5866 / 0.5834 | 4.224 / 7.602 | 256 | 420 / 388 |
| PairedTrace | 0.4782 / 0.4701 | 0.4564 / 0.4490 | 6.459 / 14.055 | 160 | 324 / 292 |

PairedTrace reduced these projection times by 29.42–35.76%, at +3.657/7.876 MiB
shared-key heap and +96 KiB workspace versus Separate. Last-three fusion needs
less key storage but 96 KiB more workspace than Paired. At N4096, Paired uses
five paired blocks and terminal R4＋SS; other lengths follow the owning rustdoc.
Choose explicitly for storage/latency needs; no automatic profile dispatch.

[Metadata](data/ntru-projection-strategies.json) retains all 60 process estimates,
CIs, order, source/patch/ELF identities, parameters and memory rows, including the
old-Paired control. Three of its four groups were slightly slower after strategy
refactoring (+0.48…+0.71%, fourth −0.15%); this is not a zero-overhead claim.
The redundant 1,800 raw samples are retired to Git `c6a6fcbe`. Online allocation
and consumer checks passed at that revision, not as current-HEAD or DFR validation.

## Historical binary complete-request gate

Binary last-layer fusion at `7c92a0b7` did not meet its whole-request gate.
Classic M16/d3/c4 or c6/o4 LUTs **including LWE return**, two reversed rounds on
CPU4/8, 20 samples/1s/4s, changed −0.90…+2.50% and −5.48…+1.25%; directions
could reverse. It remains optional, not a universal full-request improvement.
[Original samples](data/ntru-projection-fusion.csv) and [metadata](data/ntru-projection-fusion.json)
remain: use elapsed_ns/iterations; one-hot is 15 nonzero selectors, not independent
requests. The source/patch fixture is historical and not a standalone replay kit.

## Fourier paired trace (production revalidation)

The retained 2026-10-19 cohort is based on `6702a304`; [metadata](data/fourier-paired-trace.json)
binds candidate/measurement patches and source/ELF hashes, [process data](data/fourier-paired-trace.csv)
retains all three strategies and rounds. Earlier terminal-only chronology is
retired to Git; percentages from different cohorts are not added.

Native64/N4096, split40 at BR/trace/SS, sigma_f/g=1.5; n1024/h128/q2⁵²,
input/KS sigma3.2×2²⁸, KS `(L,b)=(9,2)`. Low BR/trace/SS/output:
`(3,16)/(5,11)/(5,11)/(1,19)`; High:
`(4,13)/(4,13)/(4,14)/(1,20)`. Three rotating rounds, 20 samples/0.2s/0.8s,
automatic plans, same table/base keys/BR input within each process.
Times are medians of process means, **15 selectors' complete trace＋SS** in ms
(Low / High), including ordinary output FFT but excluding BR/rotations.

| CPU | Engine | Separate | FusedLastStage | PairedTrace |
| --- | --- | ---: | ---: | ---: |
| 4 | RustFFT | 6.3748 / 5.4648 | 6.0161 / 5.1761 | 4.7420 / 4.0916 |
| 4 | TFHE-FFT | 4.6572 / 3.9903 | 4.4522 / 3.8330 | 3.9480 / 3.4052 |
| 8 | RustFFT | 5.9907 / 5.1511 | 5.6679 / 4.8821 | 4.4869 / 3.8703 |
| 8 | TFHE-FFT | 4.4309 / 3.8095 | 4.2444 / 3.6429 | 3.7443 / 3.1961 |

Versus FusedLastStage, paired projection improves 20.98–21.10% with RustFFT and
11.18–12.28% with TFHE-FFT. Complete one-hot medians improve 2.16–5.27% and
1.03–1.77%, but individual rounds regress (CPU4 TFHE-FFT High: −3.36% once).
N2048 only changes ring length as an odd-depth diagnostic; TFHE-FFT complete
one-hot medians are −0.48…+0.17%. It is not a performance/security preset.
Earlier terminal-only tests also had mixed complete CBS/LUT outcomes.

| N | Added key payload vs FusedLastStage, Low / High MiB | Workspace Separate / Fused / Paired KiB |
| --- | ---: | ---: |
| 4096 | 5.85 / 4.78 | 96 / 160 / 288 |
| 2048 | 3.10 / 2.53 | 48 / 80 / 272 |

At N4096, FusedLastStage itself adds 352.117 / 288.094 KiB of key payload and
64 KiB workspace over Separate; identity borrows the existing SSK.
These payloads exclude container headers, shared BR/FFT/EP/split buffers,
key-generation peak and RSS. Full binary trace remains for NLEV/dual, existing
SSK supplies identity, and all branches reuse one buffer. The temporary timing
fixture held maximum scratch and an extra R2 clone; production does not.

## Fourier PairedTrace one-hot first-pair sharing

Against `590b3521`, N4096 with the Fourier profiles above, [metadata](data/fourier-one-hot-sharing.json)
and [all 240 process records](data/fourier-one-hot-sharing.csv) retain formal and
fixed follow-up datasets separately: CPU4/8, three AB/BA/AB rounds, automatic
plans, 20 samples per complete request; the CPU4 follow-up used 80 with the same ELFs.

All formal nonzero one-hot cells improve 1.37–2.94%. Full one-hot and complete
c4/d3/M16/o4 LUT do not uniformly improve: CPU4/TFHE-FFT High full one-hot has
−6.29%, +1.50%, −0.36% rounds, and CPU4/RustFFT Low LUT has
−1.18%, −0.48%, +1.78%. The fixed follow-up improves those two median cases,
but includes a −0.04% LUT round. These outcomes support selective sharing, not
universal LUT speedups; ordinary CBS is an unchanged-path control.

The one-hot evaluator caches normalized input plus three cross products: +4N
u64 words (128 KiB at N4096) and +16 inline bytes, no key/ordinary-CBS storage.
Construction reserves the cache even if later calls request only NLEV/dual;
single-target, NLEV/dual and ordinary CBS use their original schedules.
Shared products correlate target errors. The [phase contract](../development/bootstrapping-contracts.md)
owns native remainders, branch rounding and consumer propagation; fusion does
not remove floor bias or prove a smaller noise budget. Finite consumer checks
and zero online allocations are not security or full-request DFR certificates.
