# BFV HPSPOVERQ: complete requests and resource costs

> 本文保留当时HPSPOVERQ的历史测量范围；当前新增的临时工作基、深度准入与完整请求对照见[HPSPOVERQLEVELED](bfv-hps-over-q-leveled.md)，Native Hybrid见[专题](native-hybrid-keys.md)。

HPSPOVERQ is an explicit ordinary BFV multiplication choice. The default
`BfvMultiplication::try_new` remains `Exact`; select the optimized backend with
`try_with_backend(context,key,BfvMultiplicationBackend::HpsPOverQ)`. Each owner
prepares only the chosen backend's resources and returns the same degree-one,
same-level native ciphertext type. The [evaluation contract](../development/bfv-evaluation.md#hpspoverq-backend)
derives its bounded one-sided prescaling, centered wrap and exact t/P rounding.
Construction alone does not certify evaluated noise, depth or security.

## Workload and identity

Measured on 2026-11-04, Ryzen 9 9955HX3D, one process/worker at a time, stable
Rust 1.98.1 release, `RUSTFLAGS=''`, Cargo `simd` off. NTT intrinsics still use
runtime CPU dispatch; this is **not a forced-scalar measurement**. Both backends
use the same compiled consumer, context, deterministic setup/input RNG sequence,
Q, secret distribution, encryption errors and native radix-16 relinearization.
Context/key/setup is outside request timing. Allocator counters instrument both
branches identically and use the system allocator.

Each sample measures one complete fresh request: allocate/encode two N=8192
coefficient plaintexts, two public encryptions, allocate output, multiply/relin,
allocate/decrypt, verify all N coefficients and checksum, then drop the request
objects. The public message has coefficients `((i+sample)%7)-3`; the second
message is `[3,-1,0,2,-2,1,0,-1]` followed by zeros. Independent Python integer
negacyclic convolution verifies every sample checksum. t=65537, secret is uniform
ternary, public encryption ephemeral is CBD1, error is CBD21, and key modulus is
Q. These are functional comparison profiles, not certified security presets.
The profile names identify the data Q reused from the earlier cross-library
comparison; both columns below are **Primus**.

| Profile | Ordered data/key Q | Exact computation P | HPSPOVERQ computation P |
| --- | --- | --- | --- |
| SEAL-Q150 | [1125899905351681,1125899905744897,1125899906629633] | [1152921504606830593,1152921504606748673,1152921504606683137] | [1152921504606830593,1152921504606748673] |
| OpenFHE-Q120 | [1152921504606830593,1152921504606748673] | [1152921504606683137,1152921504606601217,1152921504606584833] | [1152921504606683137,1152921504606601217] |

Auxiliary P is computation-only. The default HPS resource budget differs from
Exact's P>NQ requirement; explicit bases still require their own complete error
analysis. No encryption or evaluation-key modulus is enlarged.

## Results

Three alternating ABBA/BAAB cycles per profile, four processes per cycle,
nine requests per process: 24 processes and 216 complete requests, with no
warmups or adverse samples discarded. Each profile/backend has 54 samples.

| Profile | Complete request median, Exact → HPS | Change | Multiply/relin median, Exact → HPS |
| --- | --- | --- | --- |
| SEAL-Q150 | 38.559 → 36.269 ms | −5.94% | 31.384 → 29.095 ms |
| OpenFHE-Q120 | 28.905 → 26.597 ms | −7.98% | 23.560 → 21.247 ms |

Complete-request reductions in the individual cycles were 5.84/6.03/5.88% and
7.97/7.89/8.07%. This supports retaining the backend for these workloads;
it is not a claim about arbitrary parameters, deep circuits or equal-security
cross-library speedups. The asymmetric HPS square performs the actual right-side
prescaling and does not use Exact's three-product square shortcut.

| Profile | Owner live requested heap, Exact → HPS | Change | Owner preparation median, Exact → HPS | Process maximum RSS median, Exact → HPS |
| --- | --- | --- | --- | --- |
| SEAL-Q150 | 6,416,040 → 4,761,368 bytes | −25.79% | 0.556 → 0.438 ms | 16,682 → 15,018 KiB |
| OpenFHE-Q120 | 5,367,408 → 3,843,720 bytes | −28.39% | 0.574 → 0.429 ms | 12,890 → 11,444 KiB |

Owner heap includes its prepared auxiliary tables/constants, multiplication
scratch, quadratic buffer and relinearization scratch; shared context/keys are
already alive. Owner setup peak equaled its retained heap in every process.
RSS is a kernel process maximum and includes the later allocation probe and
reporting; it is not online heap or an isolated multiplication peak. Total
context/key/owner setup medians were 13.960→14.112 ms and 8.816→8.437 ms;
setup is therefore not claimed to improve uniformly.

After the timed samples, each process runs three complete prepared `_to`
requests (encrypt twice, multiply/relin, decrypt and full verify). All 72 report
zero allocations, zero live-heap change and zero peak growth. The measured ELF
has 816,706 text bytes and is 1,075,720 bytes on disk; this is the instrumented
consumer containing both backends, not an isolated library-size growth claim.
The implementation adds one RNS preparation/workspace pair and one private BFV
kernel, a small explicit backend enum and constructors, rather than another
public ciphertext representation or an evaluation-key backend.

## Correctness and current boundary

Independent integer tests cover >128-bit bases, 62-bit limb boundaries,
centered half boundaries with exact fallback, `u64::MAX` scale, signed t/P
rounding, actual kappa=1 prescaling wraps, all prepared Q prefixes, asymmetric
squares and complete relinearized phases. Tests compare HPS tensors with their
own integer specification and explicit residual bound; they do not demand byte
equality with Exact or relax an arbitrary tolerance. A separate integer/Fraction
oracle checks the wrap cancellation and phase identity.

A separate diagnostic runs 12 fresh N8192 requests under these same two Q profiles,
extracts the actual complete post-relinearization phase through the existing
partial-phase API, and reconstructs it with independent Python integer CRT.
All 98,304 coefficients satisfy the strict codec inequality, checked by exact
integer cross multiplication, rather than inferred from successful decryption.

| Profile | Maximum observed absolute centered phase error, Exact → HPS | Maximum codec inequality left side, Exact → HPS |
| --- | --- | --- |
| SEAL-Q150 | 282,693,984,939 → 54,064,193,848,996,394,514 | 1.30104e-18 → 1.30353e-18 |
| OpenFHE-Q120 | 285,000,694,678 → 277,292,859,044 | 8.81414e-19 → 8.81034e-19 |

The left side must be below 1/2 and includes the decoder's `L/gamma` term.
The Q150 resource choice has substantially larger observed phase error; its
remaining recovery margin is large for these single-product inputs. Performance
and memory savings therefore do not establish equal noise or depth capacity.
These are actual finite requests, not worst-case circuit or failure-probability
certificates. Raw phase diagnostics stay local; the evidence contains source,
input/output hashes and exact rational summaries without a secret export.

Stable batching/no-default/nightly scheme+RNS regression matrices passed
164/153/164 tests. Strict Clippy/rustdoc, ordinary external consumers and both
branches of the full leveled slot benchmark smoke passed. SSLE stable,
no-default and nightly each passed 108 tests plus public memory/TCP consumers.
The four-round raw mixed lookup retains its unscaled tensor/fresh-relin path;
it does not call this ordinary BFV multiplication backend. Its existing
statistical certificate is not extended to arbitrary HPS circuits.

The exact backend remains the default until an actual caller chooses and
validates the additional error terms. Native Hybrid evaluation keys, automatic
parameter/noise/depth management and HPSPOVERQLEVELED are separate work.

## Evidence and remeasurement

The [compressed evidence](data/bfv-hps-over-q-2026-11-04.json.gz) records every
process/sample, environment, actual binary hash, normal dependency inputs and
source bytes, consumer source/lock/build inputs, independent oracles and check
logs. It contains no measurement ELF and does not promise automatic replay on
a different toolchain or checkout. Original cross-library timing records remain
historical; the old OpenFHE `GetParamsRl()` metadata field selected prefix 0,
whereas actual HPSPOVERQ multiplication selects `GetParamsRl(sizeQ-1)` (two
60-bit primes for the Q120 profile). The preserved evidence includes the fixed
upstream source identity and a fresh metadata-only confirmation.

The maintained benchmark runs a complete fresh slot chain for both backends:
encode two inputs, public encrypt twice, multiply/relin, square/relin, rotate,
Alice→Bob switch, two prime drops, recover/decode. Setup and reusable buffers
are excluded. It is a different workload from the allocating N8192 comparison.

```sh
cargo bench -p primus_bfv --bench multiplication --features batching
cargo bench -p primus_bfv --bench multiplication --features batching -- --test
cargo nextest run -p primus_rns -p primus_bfv --lib --tests --features batching
```
