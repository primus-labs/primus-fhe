# primus_glwe_rns

English | [简体中文](README.zh_CN.md)

GLWE encryption and evaluation over an ordered RNS basis, using CRT coefficients
and DCRT NTT values. Raw ciphertexts store `[a_0,…,a_(k−1),b]` with phase
`b−Σa_i*s_i`. This crate supplies codec-free phase encryption, gadget products,
automorphism, trace, expansion and key switching. For ordinary coefficient/slot
messages use [BFV](../primus_bfv/README.md) or [BGV](../primus_bgv/README.md).
The workspace API and numerical contracts remain experimental.

## Codec-free raw workflow

Raw encryption accepts an already-encoded phase; it has no plaintext modulus,
BFV delta or decoder gamma. Start with these standalone examples:

| Example | Introduces |
| --- | --- |
| [raw_encryption](examples/raw_encryption.rs) | Private raw encryption, output reuse and full/partial phase extraction |
| [public_encryption](examples/public_encryption.rs) | Public-key binding, repeated raw encryption and ephemeral erasure |
| [gadget_encryption](examples/gadget_encryption.rs) | Advanced monomial GGSW encryption with an explicit decomposition |

```sh
cargo run -p primus_glwe_rns --example raw_encryption
cargo run -p primus_glwe_rns --example public_encryption
cargo run -p primus_glwe_rns --example gadget_encryption
```

1. Prepare an ordered `RNSBase`, a matching `DcrtTable` and `RnsGlweSize`.
2. Build `CrtGlweEncryptionParameters::try_new` for Gaussian noise, or
   `try_with_error_distribution` for an explicit law. CBD1 and CBD21 use exact
   `CenteredBinomial { eta: 1 }` / `{ eta: 21 }`, not a Gaussian approximation.
3. Convert a signed `GlweSecretKey` into DCRT, then bind once with
   `key.try_bind_raw(&sampling,&base,&table)`.
4. Reuse outputs with `encrypt_encoded_crt_to` or `encrypt_zeros_to`. The secret
   binding borrows existing resources and allocates no scratch.

## Prepared public encryption

Generate `DcrtGlwePublicKey` from the checked secret binding with
`secret.public_key(&mut rng)`, then prepare
`public.try_bind_raw(&sampling,&base,&table)`. Its mutable encryptor borrows the
key and owns one ephemeral workspace; the same `_to` methods reuse caller output.
Encoded CRT input is added to coefficient noise before the component's existing
NTT, without another scale or transform.

`workspace_mut().zeroize()` erases ephemeral values while retaining allocation;
import `zeroize::Zeroize`. Drop also erases scratch. Caller-owned ciphertexts are
separate. Output/workspace geometry is checked before sampling or writes;
canonical input and actual key/NTT provenance remain caller contracts.

## Encoding and representation

With m moduli, raw storage has `(k+1)*m*N` elements in
`[component][modulus][coefficient/evaluation]` order. CRT and DCRT have the same
shape but distinct arithmetic; use checked sizes and semantic iterators. See
[ciphertext layouts](../primus_lattice/README.md#storage-and-layout).

`key.phase_to(input,output,base.moduli())` writes the complete DCRT phase;
`partial_phase_to` writes only `−Σa_i*s_i`. They need no sampler, transform table
or allocation. Sum additive partial shares and add b **exactly once**. Inverse
NTT and recovery are explicit; these primitives provide no opening privacy,
authorization or retry policy. Complete layouts/modulus order are checked before
writes; matching numbers do not establish actual secret or NTT identity.

BFV/BGV native `[c0,c1]` and phase `c0+c1*s` are separate scheme semantics.
Use BFV's explicit raw import/export at a real raw-consumer boundary; equal
lengths do not authorize reinterpreting those buffers as mask/body ciphertexts.

## Parameter composition

`CrtGlweEncryptionParameters` owns layout and sampling precomputation, without a
codec. Noise is sampled once as a signed coefficient and lifted consistently to
all RNS limbs; secret and noise support must fit every q_i. Fixed secret weights
apply to the complete kN key. Construction establishes neither a complete
recovery/noise bound, NTT availability nor a security level.

`CrtGlevParameters::try_new(size,base,log_basis,levels)` owns the gadget base,
decomposition and weights, without sampling or BFV scaling. `try_from_parts`
accepts an independently prepared basis and checks its complete pairing. The
basis must match Q and its fixed-width limbs; radix is strictly below every q_i.
Gadget encryption/key generation receives sampling separately, so independent
roles can select different error laws. Full contracts: [sampling](src/parameter/core.rs)
and [gadget parameters](src/parameter/gadget.rs).

## Evaluation resources

`try_bind_gadget(&gadget,&sampling,&table)` returns a secret `DcrtGlevEncryptor`
or public `DcrtGgswEncryptor`. GLev has distinct CRT/DCRT input methods; GGSW
monomial encryption applies gadget weights. Its `_to` form reuses output while
the allocating convenience returns a new result. The advanced example prepares
only this additional resource. Scheme authors can fuse encoding through
`encrypt_with_body_to` / `encrypt_with_components_to`; their callback contracts
own canonical ranges, message/noise semantics and callback costs.

Clients generate keys; evaluators borrow keys, arithmetic parameters and tables,
and own mutable scratch. Constructors check complete numerical bindings before
allocation. Online calls check complete layouts before writes, while actual
roots/order, secret identity and accumulated noise remain caller obligations.
Independent workers use independent mutable evaluators.

| Evaluator | Input → output | Preparation |
| --- | --- | --- |
| `CrtGlweAutoEvaluator` / `DcrtGlweAutoEvaluator` | CRT / DCRT under the original secret | Automorphism key, gadget and actual table |
| `DcrtGlweKeySwitchEvaluator` | CRT Q → DCRT Q | `try_new(&key,&gadget,&table)` |
| `HybridRnsGlweKeySwitchEvaluator` | DCRT Q → DCRT Q | `try_new(&key,&hybrid_rns,&qp_table)` |

[Hybrid key generation](src/key_switch/hybrid/generation.rs) checks the input
secret layout, both polynomial lengths, the ordered Q basis and QP table, and the
error sampler's magnitude bound against every QP modulus. The caller must ensure
that each signed coefficient in both secrets has magnitude below every QP
modulus, including for imported keys. See
[signed secret conversion](src/secret_key/dcrt/conversion.rs) for the bounded lift.
Evaluator preparation checks the ordered QP basis and partitioning. Conversion
scratch has the larger ModUp/ModDown capacity because these phases are sequential.
Other simultaneously live buffers remain separate. See the [Hybrid RNS numerical
contracts](../primus_rns/README.md#hybrid-rns).

## Trace and coefficient expansion

These prepared evaluators preserve inputs and overwrite caller outputs/scratch.
The target messages below omit evaluation error:

| Operation | Target message |
| --- | --- |
| CRT/DCRT `trace_to` | Constant `N*m[0]` |
| DCRT reverse `trace_to` | Constant `m[0]` |
| `expand_coefficients_to` | N outputs, constant `m[j]` |
| `expand_partial_coefficients_to` | Power-of-two d outputs; `Σ_k m[j+k*d]X^(k*d)` |
| `expand_supported_coefficients_to` | Any k outputs, constant `m[j]` when plaintext degree < k |

Reverse trace divides by 2 **mod Q**, not by rounding or modulus switching.
Later switching errors need not be constant. Partial expansion retains higher
plaintext coefficients in their classes; supported expansion requires a caller
proof of degree < k, which encrypted input cannot establish. It normalizes by
`next_power_of_two(k)^−1 mod Q`, uses k−1 automorphisms and doubles existing error
on already-scalar leaves; operation counts do not certify noise or security.
See [reverse trace](src/dcrt/rev_trace.rs), [CRT expansion](src/crt/expand_coeff/evaluator.rs)
and [DCRT expansion](src/dcrt/expand_coeff/evaluator.rs) for full contracts.

Parallel expansion reserves a positive `worker_count` scratch budget and uses
the caller's Rayon pool, without creating an inner pool. The budget need not
equal thread count; complete input/output geometry is checked before writes.

## Ordinary RLWE parameter preparation

`rlwe_parameters` provides cold validation of caller-supplied u64 primes and
bounded NTT-prime search, optionally requiring `q ≡ 1 (mod t)`. Validation checks
distinct primes, `q < 2^62` and `2N | q-1`; plaintext and error budgets remain
with BFV/BGV.

`security_input` records each actual secret-bearing Q or Hybrid QP domain,
its exact product and actual sampler laws for an external review. It borrows
already-prepared rank-one sampling parameters without reconstructing Gaussian
tables from separate distribution fields. The reported basis may differ from
the original sampling basis; this diagnostic is not a context/key binding.
It always returns `NotEvaluated`: the helper does not run a security estimator or
establish a requested 128-bit target. BFV computation-only tensor/HPS primes
are excluded. Retained top-Q public material and working-basis keys must be
listed separately; drops do not erase earlier exposure. Ring-row independence,
joint-material and circular/KDM assumptions still require review.

## Benchmarks

The [raw phase benchmark](benches/raw_phase.rs) times automorphism, ordinary and
reverse trace, and serial or two-worker coefficient expansion separately. Each
uses the CRT or DCRT form of the same ciphertext with an unscaled raw phase.
Preparation is outside timing, including when a Criterion filter selects one
operation.

```sh
cargo bench -p primus_glwe_rns --bench raw_phase
```

## Features and further reading

Default features are empty; RNS dependencies are enabled without a separate
`rns` switch. `simd` forwards nightly SIMD features. Runtime NTT intrinsic dispatch
is independent of that flag; disabling it does not force scalar NTT.

`parallel` enables bounded DCRT prefix forward/inverse NTT scheduling in the
shared GLev and Hybrid paths. Each prefix with N≥4096 and at least two limbs
uses at most four contiguous tasks; bound the current pool's total threads with
`RAYON_NUM_THREADS` or `ThreadPool::install`. It is off by default, leaving this
NTT path serial without pool initialization. Random sampling is not parallelized.

[Public API sources](src/lib.rs) · [Library usage guide](../../guides/development/README.md)
· [Testing and feature boundaries](../../guides/development/testing.md)
