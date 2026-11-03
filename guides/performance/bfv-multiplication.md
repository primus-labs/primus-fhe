# Exact BFV multiplication and complete slot requests

Measured on 2026-11-03, Ryzen 9 9955HX3D, CPU 0 affinity, stable Rust 1.98.1,
release/native, System allocator, one Rayon thread, `batching` without optional
Primus SIMD. These are functional demonstration parameters, not security presets.
The [data](data/bfv-multiplication-2026-11-03.json) records actual Cargo artifacts,
binary hashes, 725 source inputs, machine information and original Criterion
samples; [CSV](data/bfv-multiplication-2026-11-03.csv) contains 200 derived rows.

The [benchmark](../../crates/primus_bfv/benches/multiplication.rs) uses N=1024,
256 plaintext subring slots, 113 active inputs, t=12289, three approximately
50-bit Q primes and three approximately 60-bit computation-only P primes.
P>NQ is checked exactly. Two independent processes used 20 samples per workload,
one second warmup and two seconds requested measurement. Compilation, tests and
other verification processes had finished before sampling.

| Operation | Process 1 mean | Process 2 mean |
| --- | ---: | ---: |
| Exact RNS NTT multiplication | 478.889 µs | 477.614 µs |
| Exact integer schoolbook reference | 85.147 ms | 85.401 ms |
| Complete fresh slot request | 1.300564 ms | 1.300550 ms |

The two kernels consume the same encrypted inputs and produce exactly equal
scaled quadratic components. Both include integer lifting, tensor computation
and t/Q scale-and-round. The default RNS NTT path is approximately 178 times
faster than this deliberately simple executable reference at these parameters.
This comparison does not rank it against optimized approximate RNS BFV libraries.
The [evaluation contract](../development/bfv-evaluation.md) establishes its exact
integer target and auxiliary capacity bound.

One complete request includes encode/embed of both inputs, two fresh public
encryptions, ciphertext multiply/relin, square/relin, first rounded drop,
encrypted row rotation, Alice-to-Bob key switching, second rounded drop, Bob's
full-N recovery and subring extract/decode. Setup, keys, tables, buffers and
independent expected-slot calculation are outside timing. Each process first
passes an executable correctness smoke and checks all output slots and
off-subring zeros. Prepared coefficient workflows separately verify zero online
allocations, including both multiplication paths and native keys.

An unchanged coefficient request from the step-06 executable is a separate ABBA
control: private encrypt, linear/plaintext evaluation, two drops and recovery.
Its source is byte-identical. Old process means were 65.150/65.357 µs; current
means were 65.528/65.866 µs, a combined +0.68%. This small observed difference is
not a step-11-only regression estimate: the frozen binary precedes intervening
changes, and two processes do not characterize broad machine variation.

Exec-isolated `/usr/bin/time` correctness smokes observed 8448/8600 KiB peak RSS
for the multiplication benchmark process. This includes all untimed setup,
keys/tables, both default/reference workspaces, assertions and Criterion; it is
neither per-request live memory nor an allocation-traffic measure. The unchanged
control smokes observed 5092–5232 KiB. Statistical timing does not include Cargo
or Python startup. Source and binary hashes remained unchanged during preparation
and measurement.

Reproduce the workload with:

```sh
cargo bench -p primus_bfv --bench multiplication --features batching -- --test
cargo bench -p primus_bfv --bench multiplication --features batching
```

Smoke and statistical measurement are separate checks. A new compiler, parameter
family, NTT convention or algorithm needs new correctness and timing evidence.
