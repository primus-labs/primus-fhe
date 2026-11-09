# Native Hybrid keys: full requests and resources

Native BFV/BGV can explicitly select Radix or Hybrid evaluation keys. The
[key contract](../development/native-hybrid-keys.md) describes fixed full-chain
partitions, exact signal reconstruction, QP key columns and scheme-specific
ModDown. Both use the native plus phase. Ordinary BFV multiplication can
independently select Exact or HPSPOVERQ; its computation P is separate from the
Hybrid evaluation-key P.

## Workload

Measured on 2026-11-04, Ryzen 9 9955HX3D, stable Rust 1.98.1 release, one
process/thread at a time, system allocator with identical allocation counters.
`RUSTFLAGS=''`, Cargo `simd` off; NTT still uses runtime CPU intrinsic dispatch.
This is not a forced-scalar comparison. The same compiled normal-dependency
consumer selects both key backends. A separate online RNG stream keeps incoming
plaintexts and ciphertexts identical despite different key-generation draws.

Every request allocates/encodes two coefficient plaintexts, performs two public
encryptions, allocates output, multiplies/relinearizes, allocates/decrypts,
verifies/checksums all N=8192 coefficients and drops the request objects. Context,
key generation and evaluator preparation are measured separately. p=65537,
secret uniform ternary, public encryption ephemeral CBD1 and errors CBD21.
Radix uses16 bits/full default digits; Hybrid uses alpha1. The retained common
JSON field `digit_size:16` describes the Radix control only; it is unused by
Hybrid. The archive includes an explicit backend/partition interpretation of
all10 recorded configurations without altering the raw outputs.

The messages are `((i+sample)%7)-3` and `[3,-1,0,2,-2,1,0,-1]` followed by zeros.
Independent Python negacyclic integer convolution checks every checksum. The
five workloads have three alternating ABBA/BAAB cycles, four processes/cycle,
nine requests/process:60 processes,540 requests,54 samples per workload/backend.
There are no discarded warmups or adverse samples.

| Workload | Ordered data Q | Hybrid key P |
| --- | --- | --- |
| BFV Q150, Exact/HPSPOVERQ | [1125899905351681,1125899905744897,1125899906629633] | [1152921504606584833] |
| BFV Q120, Exact/HPSPOVERQ | [1152921504606830593,1152921504606748673] | [1152921504606584833] |
| BGV Q170 | [144115183747268609,144115136501907457,72057594021150721] | [281474976546817] |

These are functional benchmarks, not certified security profiles. Their earlier
SEAL/OpenFHE-derived data-Q names identify parameters; every timing below is
Primus. Radix keys expose Q and Hybrid keys expose QP, so these are same-data
arithmetic comparisons, without an equal-security speedup claim. BFV's actual
computation P arrays are recorded for every process and are identical across its
two key backends. Nothing reuses a key P merely because multiplication also uses
an auxiliary basis.

## Results

| Workload | Complete request median, Radix → Hybrid | Change | Key live heap, MiB | Evaluator live heap, MiB |
| --- | --- | --- | --- | --- |
| BFV Q150 Exact | 39.492 →36.771 ms | −6.89% | 3.376 →1.895 | 6.119 →6.736 |
| BFV Q150 HPSPOVERQ | 37.198 →34.681 ms | −6.77% | 3.376 →1.895 | 4.541 →5.158 |
| BFV Q120 Exact | 29.740 →28.487 ms | −4.21% | 1.751 →1.144 | 5.119 →5.611 |
| BFV Q120 HPSPOVERQ | 27.309 →26.085 ms | −4.48% | 1.751 →1.144 | 3.666 →4.158 |
| BGV Q170 | 20.443 →15.962 ms | −21.92% | 3.751 →1.895 | 1.195 →1.813 |

The key figure includes preparation of its actual shared Hybrid parameters;
evaluator live heap counts only the additional owner/scratch. Sharing an Arc
does not allocate another parameter payload. These categories exclude common
context, public key and secret. Kernel max RSS, peaks, preparation latency and
all per-process values are preserved separately; live heap is not process RSS.
Key preparation medians for the same row order were11.264→8.379,
10.832→8.594,6.209→5.498,6.518→5.404 and14.325→8.552 ms.

All540 requests passed, including HPSPOVERQ with the new keys. Another three
complete prepared `_to` requests per process passed allocation counters
`[0,0,0]` (alloc/realloc/dealloc):180 checks total. Their prepared scratch and
caller outputs remain live outside the measurement. This does not claim zero
allocation for allocating APIs, setup, transport or a complete election.

These results justify retaining an explicit backend choice. Performance,
decomposition width, QP exposure and noise differ; no universal default, arbitrary
depth or protocol parameter certificate follows from this benchmark. The raw
fresh lookup path retains its distinct one-use unscaled contract.

## Reproducibility

The [evidence archive](data/native-hybrid-keys-2026-11-04.json.gz) contains the
normal consumer, its lock/metadata/dependency source bytes, actual binary hash,
compiler/build logs, host/feature/flags, all60 processes and540 request samples,
180 allocation checks and independent checksums. It also retains initial failed
preflights and their explanation; no stale binary output was promoted into the
formal capture. Mathematical implementation/peer reviews and test receipts are
included. Source hashes are checked before/after each formal process.

Protocol keys require their own complete QP/security/statistical acceptance;
the SSLE workspace records this separately with larger fixed ring dimensions,
independent Square keys, authenticated ceremony bindings and real four-round
memory/TCP executions. Those results are not replaced by these ordinary timings.
