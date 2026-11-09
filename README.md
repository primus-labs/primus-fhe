# Primus FHE

English | [简体中文](README.zh_CN.md)

Primus FHE is an experimental Rust workspace for fully homomorphic encryption. It provides arithmetic and lattice primitives, LWE/GLWE/NTRU encryption, and GLWE NTT, GLWE Fourier and NTRU NTT TFHE backends.

> [!WARNING]
> APIs, representations, algorithms and crate boundaries may change incompatibly without deprecation. Example and benchmark parameters are functional fixtures, not security or failure-probability recommendations. The project does not claim production readiness.

## Start here

- **Evaluate encrypted functions:** choose PBS, ManyLUT, MVB, CBS or Boolean gates in the [TFHE operation and encoding guide](crates/primus_tfhe/README.md), then select a backend below.
- **Use encryption primitives:** start with [LWE](crates/primus_lwe/README.md), [GLWE](crates/primus_glwe/README.md), [NTRU](crates/primus_ntru/README.md) or [RNS GLWE](crates/primus_glwe_rns/README.md).
- **Compose lower-level components:** the [library usage guide](guides/development/README.md) covers arithmetic domains, storage, iterators, transform representations and workspaces.

Run a complete encryption → lookup → decryption example from the repository root:

```sh
cargo run --release -p primus_tfhe_glwe_ntt --example ntt_basic
```

The example selects an `experimental` operation config, builds a context and paired keys, and applies two successive PBS calls. Client/server roles are separate; keys, LUTs, evaluator and output buffers are reused. Each backend README links complete examples for other operations.

## TFHE backends

| Family | NTT: explicit prime ring modulus | Fourier: native word ring modulus |
| --- | --- | --- |
| [GLWE parameters and clients](crates/primus_tfhe_glwe/README.md) | [GLWE NTT](crates/primus_tfhe_glwe_ntt/README.md) | [GLWE Fourier](crates/primus_tfhe_glwe_fourier/README.md) |
| [NTRU parameters and clients](crates/primus_tfhe_ntru/README.md) | [NTRU NTT](crates/primus_tfhe_ntru_ntt/README.md) | — |

GLWE supports both PBS orders. NTRU uses independent external LWE and ring secrets, with a return path from ring modulus Q to external modulus q. Invertibility applies to the ring secret; external binary/ternary secrets have no odd-weight requirement. The GLWE Fourier ring uses `NativeModulus`, with RustFFT or TFHE-FFT; NTRU's external q is independently configurable.

See the [capability table](crates/primus_tfhe/README.md#crate-map-and-capabilities) for classic and sparse coverage. Operation configs bind message moduli and key domains; contexts prepare the corresponding clients and LUT compilers. Raw ciphertexts do not carry encoding or key identity.

## Workspace map

| Layer | Crates and responsibility |
| --- | --- |
| Storage and integers | [primus_data](crates/primus_data/README.md): contiguous storage; [primus_integer](crates/primus_integer/README.md): integer traits and multi-limb arithmetic; [primus_gcd](crates/primus_gcd/README.md): GCD and modular inverses |
| Modular arithmetic | [primus_reduce](crates/primus_reduce/README.md): modulus-side traits; [primus_modulus](crates/primus_modulus/README.md): modulus implementations; [primus_factor](crates/primus_factor/README.md): prepared multiplication; [primus_barrett_derive](crates/primus_barrett_derive/README.md): constant Barrett moduli |
| Polynomials and transforms | [primus_shape](crates/primus_shape/README.md): checked polynomial lengths; [primus_poly](crates/primus_poly/README.md): polynomial representations and arithmetic; [primus_ntt](crates/primus_ntt/README.md): exact transforms; [primus_fft](crates/primus_fft/README.md): Fourier tables and reusable scratch |
| Decomposition and RNS | [primus_decompose](crates/primus_decompose/README.md): signed gadget decomposition; [primus_rns](crates/primus_rns/README.md): residue bases, conversion, and hybrid RNS |
| Sampling and encoding | [primus_distr](crates/primus_distr/README.md): secret/noise distributions; [primus_encoding](crates/primus_encoding/README.md): Rounded, Scaled, and BFV RNS coefficient codecs |
| Ciphertext representations | [primus_lattice](crates/primus_lattice/README.md): storage, arithmetic, extraction, gadget products, CMUX, and reusable workspaces |
| Encryption and evaluation | [primus_lwe](crates/primus_lwe/README.md), [primus_glwe](crates/primus_glwe/README.md), [primus_ntru](crates/primus_ntru/README.md): keys and scheme primitives; [primus_glwe_rns](crates/primus_glwe_rns/README.md): CRT/DCRT GLWE and hybrid-RNS key switching |
| TFHE | [primus_tfhe](crates/primus_tfhe/README.md): shared external LWE clients, LUTs, PBS traits, and Boolean evaluation; the two family crates and three backends above bind parameters, keys, and execution |

RNS and encoding components are building blocks; complete BFV, BGV and CKKS application backends are not implemented.

Application libraries live in separate sibling repositories: [primus_omr](../primus_omr/README.md) provides clue detection, board encoding and message recovery; [primus_high_prec_lut](../primus_high_prec_lut/README.md) provides high-precision lookup over independently encrypted chunks. Run their examples, tests and benchmarks from their own repository roots. They are not workspace members.

## Building and further reading

Default features use stable Rust; optional `simd` requires nightly. Run `cargo check --workspace --all-targets` or `cargo doc --workspace --no-deps` from the repository root. The repository sets `target-cpu=native`; adjust the build configuration explicitly when distributing binaries to other CPUs.

- [Testing guide](guides/development/testing.md): ordinary tests, doctests, feature coverage and separate example/benchmark smoke runs.
- [TFHE numerical contracts](guides/development/bootstrapping-contracts.md): rotation rounding, first lifting, one-hot and MVB.
- [Contribution rules](AGENTS.md) and [justfile](justfile): repository conventions and convenience commands.

## License

Licensed under either [Apache License 2.0](LICENSE-APACHE-2.0) or the [MIT License](LICENSE-MIT), at your option.
