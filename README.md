# Primus FHE

English | [简体中文](README.zh_CN.md)

Primus FHE is an experimental Rust workspace for fully homomorphic encryption.
The APIs are still evolving.

- [Modular arithmetic](crates/primus_modulus)
- [Negacyclic NTT](crates/primus_ntt) and [Fourier transforms](crates/primus_fft)
- [Residue number systems](crates/primus_rns)
- [Lattice layouts and operations](crates/primus_lattice)
- [LWE](crates/primus_lwe), [GLWE](crates/primus_glwe), [RNS GLWE](crates/primus_glwe_rns), and [NTRU](crates/primus_ntru) primitives

Build and test from the workspace root. Cargo features select the enabled representations and engines.

```sh
cargo check --workspace --all-targets
cargo test --workspace
```
