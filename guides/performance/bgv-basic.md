# BGV coefficient and subring-slot request costs

[Performance guide](README.md) · [BGV workflow](../../crates/primus_bgv/README.md)
· [Shared plaintext packing](../../crates/primus_encoding/README.md#integer-slots-and-subrings)

The BGV client recovers the exact centered integer phase under the full Q basis
and reduces it modulo p. It reuses one full-ring phase buffer and one
coefficient's CRT reconstruction scratch. Plaintext packing shares the existing
NTT backend with BFV, while each scheme retains its own lifting and recovery.
Prepared operations allocate no temporary storage; allocation checks are
separate from these timing measurements.

## Complete measured request

The 2026-11-03 measurement used the uncommitted BGV/shared-batching implementation
on base `f46ed57f6e3a94c2082a8110f79000e008cd30b0`. The
[metadata](data/bgv-basic-2026-11-03.json) identifies the actual Cargo executable
artifact, binary SHA256, changed production inputs and the aggregate hash of all 717
production/build inputs. This is historical evidence, not current-HEAD timing.
The [derived CSV](data/bgv-basic-2026-11-03.csv) retains all 20 observations;
the JSON also retains the original Criterion samples and estimates.

The request encodes a fixed 113-slot payload, pads the remaining slots to zero,
embeds 256 plaintext coefficients into the N1024 ring, generates a fresh public
encryption, adds an encoded plaintext offset, multiplies by an encoded plaintext
polynomial, recovers all N1024 coefficients, validates/extracts the subring and
decodes all 256 slots. Encryption uses fresh RNG coins each iteration; the
ciphertext and secret remain in the full N1024 ring. Per-call plaintext
preparation/NTTs and exact CRT recovery are included.

Tables, key/public-key generation, encryptor/evaluator preparation, persistent
output/scratch allocation and the constant offset/multiplier's slot encoding and
embedding are outside timing. One untimed complete invocation precedes workload
registration. The benchmark checks all 256 final slots after execution, including
zero padding. The same artifact passed `--test` smoke after preparation and
immediately before timing. Ciphertext multiplication, relinearization,
ciphertext rotations and level changes are outside this workload.

N1024, plaintext slot capacity 256, rank one, u64 residues, p12289,
ordered Q primes `[1125899426789377,1125899326117889]`, centered message lifts.
Secret and public ephemeral use exact CBD1; integer error uses the existing
truncated discrete Gaussian with sigma0.849, tail cut12 and support [-10,10],
then is multiplied by p exactly once. Input slot i is `1+i%19` for i<113,
the offset is 3 in those slots, and factor slot i is `1+i%3` in all 256 slots.

Rust1.98.1, Criterion0.8.2, release/native CPU, System allocator, default plus
`batching` features, Ryzen9 9955HX3D CPU2, Rayon1, unlocked frequency with boost.
The optional Primus nightly `simd` feature is disabled; the existing u64 NTT
backend can still select hardware SIMD at runtime. Criterion used 20 samples,
1 second warmup and a 2 second measurement target in one process.

| Workload | Mean, microseconds | 95% interval, microseconds |
| --- | ---: | ---: |
| Slot encode → fresh public encryption → plaintext add/mul → exact recovery → slots | 62.887 | 62.853–62.927 |

The Criterion regression-slope estimate is 62.889 microseconds
(95% interval 62.847–62.946). All samples are retained, including two flagged
outliers. The whole benchmark process peaked at **28,976 KiB RSS**, including
untimed setup, all persistent buffers, correctness assertions and Criterion
analysis. This is not additional memory per request.

These are diagnostic functional parameters, not a security or complete evaluated
noise admission certificate. Within-process intervals do not cover variation
between processes or machines. There is no equivalent previous implementation
baseline and no speedup claim.

## Remeasure

Build from the repository root and use Cargo JSON's
`compiler-artifact.executable`, rather than guessing the executable filename:

```sh
cargo +stable bench --offline --locked -p primus_bgv --features batching \
  --bench workflow --no-run --message-format=json
RAYON_NUM_THREADS=1 taskset -c 2 <workflow-benchmark-binary> --bench \
  --sample-size 20 --warm-up-time 1 --measurement-time 2 --noplot
```

Use `--bench --test --noplot` on the same executable for a quick correctness
smoke. Keep source inputs and the executable unchanged between correctness and
measurement, and run without other compilation or benchmark jobs.
