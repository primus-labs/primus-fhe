# Fourier first-product write: historical decision

[Performance guide](README.md) · [Fourier key-generation repair](fourier-glwe-keygen.md)

**Keep clear-then-accumulate.** On 2026-10-07, first-product overwrite improved
binary PBS and classic CBS, but sparse CBS and other consumers gave mixed
complete-request results. The candidate was removed; no workload-specific
specialization was retained. This is not proof that overwrite is inherently slow.

The frozen base was `494246cfd92a67d2f5854c62b55fa0c75fd97a6d`, Ryzen9
9955HX3D CPU4/8, Rust1.98.1/LLVM22.1.8, release/native, both FFT engines.
Nine workloads × three process pairs per CPU gave 54 pairs; one TFHE-FFT pair
had a different auto-selected plan. Setup/checks were outside each complete
request. Both candidates used the same traversal, FFT and add-back order.

Sparse CBS/TFHE-FFT CPU8 mean changes were +6.33%, +3.97%, −0.43% despite matching
plans, while all six classic-CBS/RustFFT pairs improved. The sparse fixture was
native64, n728/h32/N1024, full log8 decomposition with output log8/L2, r3/B64.
Both versions had zero online allocations; overwrite saved one clearing/read
pass, added initialization state and no buffer. Stage or code-size savings did
not establish repeatable gains across complete consumers.

These GLWE results used the former incorrect key representation and predate
later torus/FMA changes. They cannot decide current performance or validate
parameters. Keep the mixed result and reconsider only with a concrete current
workload and a fresh exact-key comparison. All original pairs and the longer
report remain available at Git `c6a6fcbe`; they are no longer an actively
maintained evidence set or a promised replay harness.
