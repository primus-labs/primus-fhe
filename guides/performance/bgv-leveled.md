# BGV multiplication, key switching and leveled slot request costs

[Performance guide](README.md) · [BGV workflow](../../crates/primus_bgv/README.md)
· [Previous coefficient/subring-slot workload](bgv-basic.md)

BGV evaluation uses native `c0+c1*s`, with a separate three-component tensor
before relinearization. Evaluation keys encrypt p-scaled gadget targets, and
the evaluator decomposes the canonical input multiplied by p^-1 modulo Q.
Both the truncation residual and key noise therefore contribute p-scaled phase error. Adjacent level changes
use the exact p-constrained quotient, rather than ordinary BFV rounding or
approximate hybrid ModDown. Every retained prime is one modulo p.

## Complete measured request

The 2026-11-03 measurement used the uncommitted implementation on base
`e01dfed0b08fef7098014698e76441e07c6aeb46`. The [metadata](data/bgv-leveled-2026-11-03.json)
binds 721 local production/build inputs with an aggregate hash and
changed-source hashes, actual Cargo artifacts, source archive SHA256, executable
hashes and original Criterion data.
This is historical evidence, not current-HEAD timing.
The [derived CSV](data/bgv-leveled-2026-11-03.csv) retains all 120 observations
from six independent processes, including any flagged outliers.

One new request encodes and embeds both slot vectors, performs two fresh public
encryptions, computes the ciphertext product and relinearizes, squares and
relinearizes again, drops one prime, rotates the encrypted rows left by one,
switches from Alice's secret to Bob's secret, drops another prime, then performs
Bob's exact full-N recovery, subring extraction and all 256-slot decoding. Fresh
RNG, transforms, gadget decomposition/residuals and exact quotient work are
inside timing. Context/tables, two client secrets, public/evaluation keys,
prepared operators, all persistent buffers and the expected-slot oracle are
outside timing. The benchmark checks every final slot and off-subring zero after
the request loop; the exact same executable passed a real Criterion `--test`
correctness smoke before each timed process.

Parameters: N1024, plaintext slot capacity 256, active 113, u64, rank one, p12289,
ordered Q `[1125899426789377,1125899326117889,1125898722088961]` (150 bits),
three prefix levels ending in a 50-bit modulus. Secret and public ephemeral use
exact CBD1. Integer error is truncated discrete Gaussian sigma0.849,
tail cut 12/support [-10,10], multiplied by p once. Gadget radix is 256; automatic
level 0 decomposition has 18 columns/drop 6 and level 1 has 12 columns/drop 4. Input
slot i is `(7*i+1)%p` for i<113, zero elsewhere; factor slot i is `1+i%3`.
Message lifts are centered; plaintext subring capacity does not shrink either
secret or ciphertext ring.

Rust1.98.1, Criterion0.8.2, stable release/native CPU, System allocator,
default+batching, Ryzen9 9955HX3D CPU2, Rayon1, unlocked frequency with boost.
The optional Primus nightly `simd` feature is disabled; the existing u64 NTT can
still select hardware SIMD. No compilation or other benchmark job ran during
formal sampling. Each process used 20 samples, 1s warmup and a 2s measurement
target. The six-process order is shown below; A/B form the equivalent-workload
ABBA control.

| Process | Mean, microseconds | Within-process 95% interval, microseconds |
| --- | ---: | ---: |
| leveled-1 | 462.847 | 462.598–463.084 |
| control-A1 | 67.068 | 67.043–67.098 |
| control-B1 | 66.898 | 66.876–66.919 |
| control-B2 | 66.969 | 66.950–66.988 |
| control-A2 | 66.851 | 66.805–66.898 |
| leveled-2 | 468.579 | 468.168–469.014 |

The new complete request cost **462.847 and 468.579 microseconds** in the
two independent processes. Their difference illustrates process variation
beyond the within-process confidence intervals. There is no equivalent previous
complete implementation and no speedup claim for this new workload.

## Equivalent existing-workflow control

A is the frozen previous executable
`4a1d939bca365f14052c0031faabd4ada40de196fd3c1573f1d9246f19b5bdcb`.
B is the current `workflow` source with only explicit level 0 API arguments added.
Both perform the same slot encode→fresh public encryption→plaintext add/mul→
exact recovery→slot decode request from the previous guide, with identical
parameters and features. The old executable's source was checked against its
frozen source archive; the original binary/target was preserved. The current
binary is `cf071cfe018e1b12eaaa8f7699f5458a099a57ec09b1778ecf0d0ab30f514fe6`.

Across the ABBA run, the two A means average 66.960 microseconds and the two B
means average 66.933 microseconds, a -0.039% difference. This does not
establish a substantive performance change. Rerunning the actual old executable
under the current conditions avoids treating differences from the earlier
calendar-time measurement as a code regression.

## Memory observation and scope

All six Python-spawn `wait4` peaks were 29,184 KiB. A separate exec-isolated
`/usr/bin/time -v` correctness smoke measured current workflow 4,972 KiB,
new leveled workflow 7,316 KiB and old control 5,216 KiB. The identical larger raw
`wait4` number includes the Python launcher's pre-exec RSS floor and must not be
reported as an isolated Rust workflow peak.

The isolated smoke includes the complete context/key/operator setup, persistent
storage, one full request and output assertions; it excludes Criterion's timed
sampling/statistical analysis. These are separate process observations, not
incremental request memory or evidence of a memory optimization. Prepared
zero-allocation behavior is tested separately.

## Remeasure

Build from the repository root and read Cargo JSON's actual
`compiler-artifact.executable`:

```sh
cargo +stable bench --offline --locked -p primus_bgv --features batching \
  --bench leveled --bench workflow --no-run --message-format=json
RAYON_NUM_THREADS=1 taskset -c 2 <leveled-benchmark-binary> --bench \
  --sample-size 20 --warm-up-time 1 --measurement-time 2 --noplot
```

Run `--bench --test --noplot` on the same executable before timing and keep
sources/binaries unchanged. For memory smoke, wrap that same command in
`/usr/bin/time -v` after an exec boundary. Retain independent Criterion homes
and original samples for repeated processes. Use the frozen old executable
and an ABBA order when checking the equivalent previous workflow.

These diagnostic parameters establish functionality, not security or a complete
evaluated noise admission certificate. Process/machine variation remains beyond
Criterion's within-process confidence intervals.
