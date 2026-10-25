# Lattice benchmarks for TFHE and RNS GLWE

> [!WARNING]
> Part of the experimental [Primus FHE](../../../README.md) workspace; APIs and numerical contracts may change incompatibly.

Choose one target to measure a lattice operation. Parameters and case names are defined in the linked source files.

| Target | Workload | Required features |
| --- | --- | --- |
| [glwe_fourier](glwe_fourier.rs) | GGSW external product, monomial CMux, fused/two-CMux ternary rotation; both FFT engines | `rustfft,tfhe-fft` |
| [glwe_ntt](glwe_ntt.rs) | GGSW coefficient/NTT-output external product, monomial CMux, fused/two-CMux ternary rotation | `ntt` |
| [ntru_fourier](ntru_fourier.rs) | NGSW coefficient/Fourier-output external product and monomial CMux; both FFT engines | `rustfft,tfhe-fft` |
| [ntru_ntt](ntru_ntt.rs) | NGSW coefficient/NTT-output external product and monomial CMux | `ntt` |
| [extraction](extraction.rs) | Full NTRU extraction, compact GLWE extraction and inverse GLWE extraction | None |
| [rns_glev](rns_glev.rs) | CRT/BigUint polynomial × DCRT GLev, with DCRT output or accumulation | `rns` |
| [rns_ggsw](rns_ggsw.rs) | CRT GLWE × DCRT GGSW, with DCRT output | `rns` |

## Measurement boundaries

One iteration runs one labeled workload with preallocated output and scratch; the two-CMux case includes both calls. Data generation, tables and gadget transforms are outside timing; required initialization and output conversion remain inside. Throughput counts logical output coefficients or RNS residues, including the LWE body for extraction.

Coefficient-output and transform-output products have different endpoints. The RNS BigUint case starts with a precomposed input, so its timing excludes CRT recomposition. Ternary fused/two-CMux cases share controls and input and return coefficients, but their decomposition and rounding errors need not match.

Fixtures use deterministic arithmetic data and reused working sets, not sampled encrypted controls or recommended secure parameters. Compare equivalent workloads on the same host, toolchain and features. These timings do not establish equal-security performance or sequential bootstrapping-key bandwidth; confirm gains in complete operations in the scheme/TFHE crates.

## Commands

Run from the workspace root:

```sh
cargo bench -p primus_lattice --bench glwe_fourier --features rustfft,tfhe-fft
cargo bench -p primus_lattice --bench glwe_ntt --features ntt
cargo bench -p primus_lattice --bench ntru_fourier --features rustfft,tfhe-fft
cargo bench -p primus_lattice --bench ntru_ntt --features ntt
cargo bench -p primus_lattice --bench extraction
cargo bench -p primus_lattice --bench rns_glev --features rns
cargo bench -p primus_lattice --bench rns_ggsw --features rns
```

Append `-- '<regex>'` to select cases, or `-- --test` to execute each fixture once without collecting timings. See the workspace [testing guide](../../../guides/development/testing.md) for validation entry points.
