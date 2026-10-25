# primus_lattice

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

`primus_lattice` provides ciphertext storage, representation conversions, and low-level lattice operations for [Primus FHE](../../README.md). It is shared by the GLWE/NTRU × Fourier/NTT TFHE paths and by RNS GLWE implementations.

Key generation, encryption parameters, encoding policy, noise management, and complete homomorphic evaluation belong to higher layers such as [`primus_glwe`](../primus_glwe), [`primus_ntru`](../primus_ntru), and [`primus_glwe_rns`](../primus_glwe_rns).

## Ciphertext families

Let `N` be the polynomial length, `k` the GLWE mask dimension, `L` the gadget level count, and `m` the RNS modulus count. Polynomial arithmetic uses the negacyclic ring modulo `X^N + 1`.

| Family | Coefficient-domain layout | Available representations |
| --- | --- | --- |
| `Lwe` | Scalar mask followed by one body scalar | Coefficients |
| `MultiMsgLwe` | One length-`N` mask in constant-term extraction order, followed by retained body coefficients | Packed RLWE samples |
| `Glwe` | `k` mask polynomials followed by one body polynomial | Coefficient, NTT, Fourier, CRT/DCRT |
| `Glev` | `L` GLWE ciphertexts in decomposition order | Coefficient, NTT, Fourier, CRT/DCRT |
| `Ggsw` | `k+1` GLev rows | Coefficient, NTT, Fourier, CRT/DCRT |
| `Ntru` | One polynomial `h`, with phase `f*h` under secret `f` | Coefficient, NTT, Fourier |
| `Nlev` / `Ngsw` | `L` NTRU polynomials in decomposition order | Coefficient, NTT, Fourier |

RLWE, RLev and RGSW use `Glwe`, `Glev` and `Ggsw` with `GlweSize::new(GlweDimension::new(1), PolyLength::new(N))`; their NTT and CRT/DCRT representations follow the same dimension-one layout.

Types are exported through their modules, for example `glwe::Glwe`, `ggsw::NttGgsw`, and `ngsw::FourierNgsw`. Prefixes identify the representation. `Torus*` aliases name native-torus uses of coefficient wrappers; they do not enforce a modulus or perform encoding.

NLev and NGSW share a storage shape but have different semantics: an NLev of `beta` contains phases `v_i*beta`; an NGSW of `beta` contains phases `v_i*f*beta`. Their valid gadget products differ, so the types are intentionally distinct.

## Storage and layout

Wrappers are generic over storage `S` through [`primus_data`](../primus_data/README.md), supporting owned and borrowed data. `as_view()` / `as_mut_view()` borrow complete storage without copying or changing representation; `into_inner()` returns the original storage. Use polynomial and ciphertext iterators to traverse components, levels and rows without repacking.

`LweIter` / `LweIterMut` use chunk lengths that include the body, as returned by `Lwe::lwe_len()`. Iterators omit incomplete tails, so callers must establish complete lengths first. `MultiMsgLweIter` traverses packed containers; it does not extract individual samples from one shared mask.

- Ordinary GLWE uses `(k+1)*N` elements, GLev uses `L*(k+1)*N`, and GGSW uses `(k+1)*L*(k+1)*N`.
- CRT stores each polynomial as `m` coefficient blocks of length `N`; DCRT uses the same layout with NTT data in each block. Nested gadget order is `[row][level][component][modulus][coefficient/evaluation]`.
- Fourier polynomials contain `N/2` complex entries in backend-defined order. Ciphertexts use normalized torus transforms; polynomial multipliers must use the scale required by the operation.
- RNS GLev multiplication also accepts `primus_poly::BigUintPolynomial` inputs, stored coefficient-major with fixed-width little-endian limbs per coefficient.

`LweDimension` and `GlweDimension` represent positive mask counts; `.ciphertext_len()` and `.component_count()` return the body-inclusive `n+1` and `k+1`. They guarantee representable counts, not secure parameters. Raw ciphertext and secret-key slices can still represent dimension zero.

Allocate storage using the length accessors of `GlweSize`, `GadgetSize`, `RnsGlweSize` and `RnsGadgetSize`. These types check combined-length overflow and RNS modulus counts; `LweDimension::from(glwe_size)` derives the extracted dimension `kN`. They do not validate actual buffers, transform tables, moduli or security.

Layouts and workspaces take [`primus_shape::PolyLength`](../primus_shape/README.md#polynomial-length). Its `.get()`, `.log_n()` and `.fourier_poly_len()` return `N`, `log2(N)` and `N/2`.

## Serialization

`serde` enables serialization for `Lwe<S>` and `MultiMsgLwe<S>` when their storage supports the corresponding traits.

Only raw coefficients are serialized. Dimensions, the packed mask/body split, modulus, encoding and key identity remain external; deserialization does not validate them. This is not a versioned key or parameter format.

## Operations and ownership

| Operation family | Main interfaces |
| --- | --- |
| Basic arithmetic | `add_assign`, `sub_assign`, `neg_assign` and corresponding output forms |
| Scalar/factor arithmetic | `mul_scalar_*`, `mul_factor_*`, and supported fused accumulations |
| Polynomial operations | Monomials in coefficient/NTT form; polynomial multiplication/accumulation in NTT, Fourier, or DCRT form |
| Plaintext and gadget updates | `add_plaintext_assign`, `set_trivial`, `add_gadget_diagonal_assign` |
| Conversions | `into_ntt_form`, `write_ntt_form`, inverse coefficient conversions, `write_fourier_form`, `write_torus_form` |
| Extraction | `extract_lwe_at_to`, compact GLWE extraction, packed RLWE extraction, `inverse_extract_glwe_to` |
| External products | Fourier/NTT GGSW and NTRU gadget products; DCRT GLev polynomial products and GGSW products |
| CMUX | GGSW/NGSW `cmux_to`, `cmux_k_to`, `cmux_monomial_to` |
| Ternary rotation | NTT/Fourier GGSW and NGSW `cmux_ternary_monomial_to` |

Availability depends on the type and representation. RNS scalar/factor inputs use `primus_rns::Residues` and `ResidueFactors` in modulus order.

`*_assign` mutates its receiver, `*_to` writes a separate output, and `add_*_assign` accumulates into initialized storage. Consuming methods may reuse storage, while methods returning a new extracted sample allocate; consult the specific method contract.

External products can return coefficients or retain transformed output through `external_product_ntt_to` / `external_product_fourier_to`.

`DcrtGgsw::external_product_to` accepts a coefficient-domain `CrtGlwe` input and overwrites a `DcrtGlwe` output, using a matching RNS base, decomposition basis, transform table and `DcrtGlevMulWorkspace`.

NLev `external_product_sum_to` and GGSW/NGSW `cmux_k_to` accept exact-size iterators with matching counts. Pass borrowed gadgets and polynomial/ciphertext views, `output.as_mut_view()` for output, and `default.as_view()` for the CMux default. Candidates may come from `GlweIter` / `NtruIter` or borrowed ciphertext collections, without collecting views. Empty sums write zero; empty CMux copies its default. Fourier rounds the aggregate result, which can differ from summing separately converted coefficient products.

Full GLWE extraction flattens all mask polynomials into an LWE mask; compact extraction requires the omitted secret suffix to be zero. `MultiMsgLwe` represents one shared mask in constant-term extraction order; its extractors rotate that mask negacyclically for each retained body coefficient. Inverse extraction embeds the constant-term LWE sample and zero-fills unused storage; it does not recover every coefficient of the original GLWE plaintext.

## Correctness and workspace contracts

Raw constructors and mutable access do not establish ciphertext validity. Callers must ensure compatible keys, encodings, sizes, complete buffer lengths, modulus order, decomposition bases and transform conventions. Fourier data must use the exact FFT table instance and scale required by the operation. Unless documented otherwise, modular inputs must be canonical residues; all word values are canonical under the native modulus.

These low-level operations deliberately omit some checks. Invalid inputs may silently process only common prefixes or complete chunks. See each method's `Correctness` and `Panics` documentation in the [API sources](src/lib.rs) for exact conditions.

| Workspace | Size requirements |
| --- | --- |
| `NttGlweExternalProductWorkspace` / `FourierGlweExternalProductWorkspace` | GLWE layout and decomposition levels in `GadgetSize` |
| `NttGlweTernaryCmuxWorkspace` / `FourierGlweTernaryCmuxWorkspace` | Fixed `GadgetSize` |
| `NttNtruExternalProductWorkspace` / `FourierNtruExternalProductWorkspace` | Polynomial length |
| `NttNtruCmuxWorkspace` / `FourierNtruCmuxWorkspace` | Polynomial length and decomposition levels |
| `DcrtGlevMulWorkspace` | RNS gadget layout and product-modulus limb width |

Workspaces provide reusable scratch, without validating key, basis, table or modulus identity. Overwriting external products initialize their buffers, so valid calls need no reset; accumulating APIs require valid existing output. GLWE external-product workspace `with_rebound` temporarily changes decomposition depth while preserving the GLWE shape and restores the original layout after the call; `resize` can change buffer sizes.

Batch external products and k-CMux check iterator counts; buffer-length checks vary by operation, and some are debug assertions only. An invalid later pair or panicking iterator can leave partial output or scratch; discard the result, then reuse the workspace in a valid call. The method documentation specifies the exact checks and write boundaries.

CMux selection requires encrypted bit controls; k-CMux requires at most one active control. Ternary `cmux_ternary_monomial_to` uses mutually exclusive bits `s⁺, s⁻`, with ideal rotation `X^(exponent * (s⁺-s⁻))`. The exponent must be in `0..2N`; zero copies the input exactly. Controls must share the key, basis and transform conventions; Fourier controls use native-torus scale and a matching native basis. Noise growth and decryptability belong to higher layers.

## Example

Borrow storage, add an already encoded polynomial to the body, then extract its second coefficient under an explicit modulus:

```rust
use primus_lattice::{GlweDimension, GlweSize, glwe::Glwe, lwe::Lwe};
use primus_shape::PolyLength;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;

let size = GlweSize::new(GlweDimension::new(2), PolyLength::new(32));
let modulus = BarrettModulus::new(97u32);
let mut storage: Vec<u32> = (1..=size.glwe_len()).map(|i| i as u32).collect();
assert_eq!(storage.len(), size.glwe_len());
let mut ciphertext = Glwe::new(storage.as_mut_slice());
let plaintext = Polynomial::new(vec![10; size.poly_length().get()]);
ciphertext.add_plaintext_assign(&plaintext, modulus);

let mut sample: Lwe<Vec<u32>> = Lwe::zero(size.mask_len());
ciphertext.extract_lwe_at_to(1, &mut sample, size.poly_length().get(), modulus);
assert_eq!(&sample.a()[..2], &[2, 1]);
assert_eq!(sample.b(), 76);
```

This illustrates layout and arithmetic, not randomized encryption or secure parameter selection.

## Features

Default features are empty: coefficient storage, layouts and basic arithmetic do not pull in NTT/FFT.

- `serde` enables raw `Lwe` and `MultiMsgLwe` serialization.
- `ntt` enables NTT ciphertexts, conversions, operations and workspaces.
- `fourier` enables the corresponding generic Fourier APIs without selecting an FFT engine.
- `rustfft` / `tfhe-fft` enable `fourier` and the corresponding FFT implementation; they can be combined.
- `rns` enables CRT/DCRT ciphertexts and multiplication workspaces, including the `ntt` capability required by DCRT.
- `simd` propagates nightly SIMD only to active arithmetic dependencies; it does not activate a backend, FFT engine or `rns`.
- `RnsGlweSize` and `RnsGadgetSize` remain available without `rns`.

Each target declares the representations and concrete FFT implementations it needs. Mixed-backend comparisons require all corresponding features; Cargo skips the entire target when any requirement is missing.

## Tests and benchmarks

Validation commands are in the workspace [testing guide](../../guides/development/testing.md). The [benchmark guide](benches/README.md) lists independently runnable targets and their endpoints; measure complete PBS and sequential evaluation-key access in the upper layers.
