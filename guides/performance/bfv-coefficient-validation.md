# BFV coefficient validation at the encryption boundary

BFV's client, advanced secret-key context and public encryptor now reject
noncanonical coefficients before sampling or writing output/scratch. The actual
private/public coefficient boundaries own these checks; the client no longer
duplicates them. The codec retains its independent checks. Explicit CRT inputs
retain their documented representation preconditions.

The previous advanced entry points documented rejection after noise sampling.
This change makes invalid-input side effects consistent across ordinary BFV
coefficient workflows. Valid inputs retain the same random draws, encoding
injection and transforms. Existing same-coins coefficient/CRT comparisons and
the [boundary regression](../../crates/primus_bfv/tests/coefficients.rs) verify
these contracts; the allocation suite still observes zero online allocations.

The public path adds one canonical-input scan before sampling. Its cost was
measured in the unchanged complete [slot request](../../crates/primus_bfv/benches/multiplication.rs),
using the frozen pre-change executable and a current Cargo artifact. The benchmark
source is byte-identical. Parameters remain N1024/n256, t12289, Q150bit,
computation-only P3×60bit, two fresh public inputs, mul/relin, square/relin,
rotation, key switching, two prime drops and recovery/slot decoding. All setup,
keys, buffers and assertions are outside timing; the new check is inside it.

Measured 2026-11-03 on Ryzen 9 9955HX3D, CPU 0 affinity, stable Rust 1.98.1,
release/native, System allocator, `batching`, no optional SIMD. All other
verification processes had finished. Each process used 20 samples, one second
warmup and two seconds requested measurement; order was old/new/new/old.

| Executable | First process mean | Second process mean |
| --- | ---: | ---: |
| Before boundary change | 1.308594 ms | 1.301388 ms |
| Current | 1.307574 ms | 1.298917 ms |

Combined means are 1.304991→1.303246 ms (−0.13%). This does not establish a
speedup; it shows no material slowdown in these runs. Two processes per side
do not characterize all machine variation. The numerical multiplication, keys,
modulus switching and workload parameters were unchanged.

[Data](data/bfv-coefficient-validation-2026-11-03.json) binds the 725 current
compilation inputs, compiler artifact, actual executable hashes, parameters,
environment, correctness smokes and original Criterion samples.
[CSV](data/bfv-coefficient-validation-2026-11-03.csv) retains all 80 derived rows.
Source and executable hashes were unchanged throughout preparation and timing.
RSS fields describe exec-isolated whole-process correctness smokes, including
untimed setup and both reference/default workspaces; they are not per-request
memory. This is a performance guard for input validation, not a new security
preset or an assessment of arbitrary BFV circuits.
