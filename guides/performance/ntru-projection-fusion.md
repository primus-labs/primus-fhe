# NTRU projection strategies and costs

[Performance guide](README.md) · [NTT contract](../../crates/primus_ntru/src/scheme_switch/projection.rs)

Configure `CbsConfig.projection` before keys/workspace construction. The default
is `Separate`; NTT performance presets explicitly use `PairedTrace`.
NLEV-only/dual outputs retain separate trace/SS. The [support matrix](../development/bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support)
owns projection strategy contracts; the [LUT presets](../../../primus_high_prec_lut/guides/performance/ntru-lut-presets.md)
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
