# BFV coefficient workflow costs

[Performance guide](README.md) · [BFV workflow](../../crates/primus_bfv/README.md)
· [Phase and rounding contracts](../development/rns-phase-conventions.md#coefficient-evaluation-recovery-and-exact-prime-drop)

The coefficient evaluator reuses one plaintext CRT/NTT buffer. A rounded prime
drop reuses one N-element buffer: it inverse-transforms only the dropped input
limb and forward-transforms its centered correction in retained limbs. It does
not reconstruct full integers or inverse-transform the retained input limbs.
This choice keeps the exact component-rounding contract without online big
integers, raw-GLWE bridges or temporary allocation.

## Measured workload

The 2026-11-03 measurement used the uncommitted coefficient-workflow implementation
on base `541410bf24c107255c7429752a3c5d8d757fedfe`. The
[metadata](data/bfv-leveled-coefficients-2026-11-03.json) identifies changed source
files and the actual binary; it is historical evidence, not current-HEAD timing.
[Samples](data/bfv-leveled-coefficients-2026-11-03.csv) retain all 80 observations.

N1024, rank one, u64 Q primes `[1125899906826241,1125899906629633,1125899906031617]`,
t12289, gamma2199023190017, SparseTernary secret, Gaussian sigma3.2. Rust1.98.1,
default features, release/native CPU, system allocator, Ryzen9 9955HX3D CPU2,
Rayon1, unlocked frequency. Criterion0.8.2 used 20 samples per workload,
1 second warmup and 2 seconds measurement target in one process.

| Workload | Slope estimate, microseconds | 95% interval, microseconds |
| --- | ---: | ---: |
| Dense unscaled plaintext multiplication | 11.933 | 11.901–11.988 |
| Exact rounded drop, three primes to two | 6.663 | 6.657–6.671 |
| Exact rounded drop, two primes to one | 4.283 | 4.280–4.284 |
| Private encryption → plaintext add/mul → two drops → recovery | 65.092 | 65.074–65.120 |

The complete request includes its encryption RNG, message injection, plaintext
preparation/NTTs, both component switches and destination recovery. Setup,
key generation, persistent outputs/scratch and the independent schoolbook
correctness assertion are outside timing. Individual rows cannot be summed to
predict the full request. Prepared operations allocate no temporary storage;
the allocating recovery convenience allocates its result once. The measured
process peaked at 12524 KiB RSS, including setup, the correctness oracle and
Criterion analysis; this is not per-operation additional memory.

These are diagnostic functional parameters, not a security or complete evaluated
noise admission certificate. Within-process intervals do not cover variation
between processes or machines. There is no before/after speedup claim for these
new operations.

## Remeasure

The production benchmark performs a complete correctness assertion before
registering any workload. Run from the repository root:

```sh
cargo bench -p primus_bfv --bench leveled --no-run --message-format=json
```

Use the resulting executable artifact in a single pinned process:

```sh
RAYON_NUM_THREADS=1 taskset -c 2 <leveled-benchmark-binary> --bench \
  --sample-size 20 --warm-up-time 1 --measurement-time 2 --noplot
```

For a quick executable check without sampling:

```sh
just bench-smoke primus_bfv leveled
```
