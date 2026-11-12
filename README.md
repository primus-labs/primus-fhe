# Primus FHE

English | [简体中文](README.zh_CN.md)

Primus FHE is an experimental Rust workspace for fully homomorphic encryption. It includes arithmetic and lattice primitives, LWE/GLWE/NTRU encryption, four TFHE backends, and leveled BFV and BGV.

> [!WARNING]
> APIs, representations, algorithms and crate boundaries may change incompatibly without deprecation. Example and benchmark parameters are functional fixtures, not security or failure-probability recommendations. The project does not claim production readiness.

## Start here

- **Evaluate encrypted functions:** choose PBS, ManyLUT, MVB, CBS or Boolean gates in the [TFHE operation and encoding guide](crates/primus_tfhe/README.md), then select a backend below.
- **Use encryption primitives:** start with [LWE](crates/primus_lwe/README.md), [GLWE](crates/primus_glwe/README.md), [NTRU](crates/primus_ntru/README.md) or [RNS GLWE](crates/primus_glwe_rns/README.md).
- **Use BFV/BGV coefficients or slots:** start with the complete examples in [primus_bfv](crates/primus_bfv/README.md) or [primus_bgv](crates/primus_bgv/README.md).
- **Compose lower-level components:** the [library usage guide](guides/development/README.md) covers arithmetic domains, storage, iterators, transform representations and workspaces.

Run a complete encryption → lookup → decryption example from the repository root:

```sh
cargo run --release -p primus_tfhe_glwe_ntt --example ntt_basic
```

The example chains two lookup tables using the same keys and evaluator. Each backend README links complete examples for other operations.

## TFHE backends

| Family | NTT: explicit prime ring modulus | Fourier: native word ring modulus |
| --- | --- | --- |
| [GLWE parameters and clients](crates/primus_tfhe_glwe/README.md) | [GLWE NTT](crates/primus_tfhe_glwe_ntt/README.md) | [GLWE Fourier](crates/primus_tfhe_glwe_fourier/README.md) |
| [NTRU parameters and clients](crates/primus_tfhe_ntru/README.md) | [NTRU NTT](crates/primus_tfhe_ntru_ntt/README.md) | [NTRU Fourier](crates/primus_tfhe_ntru_fourier/README.md) |

GLWE supports both PBS orders. NTRU uses independent external LWE and ring secrets, with a return path from ring modulus Q to external modulus q. Invertibility applies to the ring secret; external binary/ternary secrets have no odd-weight requirement. Fourier rings currently support only `NativeModulus`, with RustFFT or TFHE-FFT; NTRU's external q is independently configurable.

See the [capability table](crates/primus_tfhe/README.md#crate-map-and-capabilities) for Classic and Block coverage. Operation configs bind message moduli and key domains; contexts prepare the corresponding clients and LUT compilers. Raw ciphertexts do not carry encoding or key identity.

## BFV and BGV

Both schemes provide rank-one coefficient and slot workflows with native Radix and Hybrid evaluation keys. Run one of the complete examples below.

```sh
cargo run --release -p primus_bfv --example coefficients
cargo run --release -p primus_bgv --example leveled_coefficients
```

- [BFV](crates/primus_bfv/README.md) offers Exact and HPSPOVERQ multiplication and rounded prime drop.
- [BGV](crates/primus_bgv/README.md) uses exact prime drop and ciphertext primes coprime to the plaintext modulus.

See the [parameter and budget guide](guides/development/ordinary-parameter-budgets.md) when selecting parameters for a circuit.

## Workspace map

| Layer | Crates and responsibility |
| --- | --- |
| Storage and integers | [primus_data](crates/primus_data/README.md): contiguous storage; [primus_integer](crates/primus_integer/README.md): integer traits and multi-limb arithmetic; [primus_gcd](crates/primus_gcd/README.md): GCD and modular inverses |
| Modular arithmetic | [primus_reduce](crates/primus_reduce/README.md): modulus-side traits; [primus_modulus](crates/primus_modulus/README.md): modulus implementations; [primus_factor](crates/primus_factor/README.md): prepared multiplication; [primus_barrett_derive](crates/primus_barrett_derive/README.md): constant Barrett moduli |
| Polynomials and transforms | [primus_shape](crates/primus_shape/README.md): checked polynomial lengths; [primus_poly](crates/primus_poly/README.md): polynomial representations and arithmetic; [primus_ntt](crates/primus_ntt/README.md): exact transforms; [primus_fft](crates/primus_fft/README.md): Fourier tables and reusable scratch |
| Decomposition and RNS | [primus_decompose](crates/primus_decompose/README.md): signed gadget decomposition; [primus_rns](crates/primus_rns/README.md): residue bases, conversion, and hybrid RNS |
| Sampling and encoding | [primus_distr](crates/primus_distr/README.md): secret/noise distributions; [primus_encoding](crates/primus_encoding/README.md): Rounded, Scaled, BFV RNS coefficient codecs and shared batching |
| Ciphertext representations | [primus_lattice](crates/primus_lattice/README.md): storage, arithmetic, extraction, gadget products, CMUX, and reusable workspaces |
| Encryption and evaluation | [primus_lwe](crates/primus_lwe/README.md), [primus_glwe](crates/primus_glwe/README.md), [primus_ntru](crates/primus_ntru/README.md): keys and scheme primitives; [primus_glwe_rns](crates/primus_glwe_rns/README.md): CRT/DCRT GLWE and hybrid-RNS key switching |
| BFV/BGV coefficients and slots | [primus_bfv](crates/primus_bfv/README.md): BFV parameters, scaling and recovery; [primus_bgv](crates/primus_bgv/README.md): p-scaled error and exact centered recovery; both consume shared batching |
| TFHE | [primus_tfhe](crates/primus_tfhe/README.md): shared external LWE clients, LUTs, PBS traits, and Boolean evaluation; the two family crates and four backends above bind parameters, keys, and execution |

## Building and further reading

Default features use stable Rust. Optional `simd` requires nightly. The repository sets `target-cpu=native`. Adjust the build configuration when distributing binaries to other CPUs.

- Generate the API documentation with `cargo doc --workspace --no-deps` or follow a crate's README for operation-specific features.
- Find validation commands and scripts in the [testing guide](guides/development/testing.md) and benchmark interpretation in the [performance guide](guides/performance/README.md).
- Follow the [contribution rules](AGENTS.md) for workspace changes.

## License

Licensed under either [Apache License 2.0](LICENSE-APACHE-2.0) or the [MIT License](LICENSE-MIT), at your option.
