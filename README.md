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

The example selects an `experimental` operation config, builds a context and paired keys, and applies two successive PBS calls. Client/server roles are separate; keys, LUTs, evaluator and output buffers are reused. Each backend README links complete examples for other operations.

## TFHE backends

| Family | NTT: explicit prime ring modulus | Fourier: native word ring modulus |
| --- | --- | --- |
| [GLWE parameters and clients](crates/primus_tfhe_glwe/README.md) | [GLWE NTT](crates/primus_tfhe_glwe_ntt/README.md) | [GLWE Fourier](crates/primus_tfhe_glwe_fourier/README.md) |
| [NTRU parameters and clients](crates/primus_tfhe_ntru/README.md) | [NTRU NTT](crates/primus_tfhe_ntru_ntt/README.md) | [NTRU Fourier](crates/primus_tfhe_ntru_fourier/README.md) |

GLWE supports both PBS orders. NTRU uses independent external LWE and ring secrets, with a return path from ring modulus Q to external modulus q. Invertibility applies to the ring secret; external binary/ternary secrets have no odd-weight requirement. Fourier rings currently support only `NativeModulus`, with RustFFT or TFHE-FFT; NTRU's external q is independently configurable.

See the [capability table](crates/primus_tfhe/README.md#crate-map-and-capabilities) for classic and sparse coverage. Operation configs bind message moduli and key domains; contexts prepare the corresponding clients and LUT compilers. Raw ciphertexts do not carry encoding or key identity.

## BFV and BGV

Both schemes provide rank-one coefficient and slot workflows with native Radix and Hybrid evaluation keys. Run one of the complete examples below.

```sh
cargo run --release -p primus_bfv --example coefficients
cargo run --release -p primus_bgv --example leveled_coefficients
```

- [BFV](crates/primus_bfv/README.md) provides exact rounded prime drop and Exact and HPSPOVERQ multiplication. The [working-basis guide](guides/development/bfv-working-basis.md) describes the finite HPSPOVERQLEVELED parameter factory and its arithmetic and key requirements.
- [BGV](crates/primus_bgv/README.md) supports ciphertext prime chains with each prime coprime to the plaintext modulus `p`. Dropping a prime `q` updates the correction factor to `f*q^-1 mod p`. Centered recovery applies the inverse factor modulo `p`. See the [parameter and budget guide](guides/development/ordinary-parameter-budgets.md) for the ordinary BGV workflow and its limits.

The [native Hybrid key guide](guides/development/native-hybrid-keys.md) describes the QP key basis and role bindings shared by both schemes.

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

Default features use stable Rust; optional `simd` requires nightly. Run `cargo check --workspace --all-targets` or `cargo doc --workspace --no-deps` from the repository root. The repository sets `target-cpu=native`; adjust the build configuration explicitly when distributing binaries to other CPUs.

- Run ordinary tests, doctests, examples and benchmark smoke tests using the [testing guide](guides/development/testing.md) and [justfile](justfile).
- Find the BFV/BGV external consumer check and parameter screening adapter under [developer scripts](guides/development/testing.md#开发脚本).
- See the [performance guide](guides/performance/README.md) for benchmark interpretation and the [TFHE numerical contracts](guides/development/bootstrapping-contracts.md) for algorithmic requirements.
- Follow the [contribution rules](AGENTS.md) for workspace changes.

## License

Licensed under either [Apache License 2.0](LICENSE-APACHE-2.0) or the [MIT License](LICENSE-MIT), at your option.
