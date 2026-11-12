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
`public.try_bind_raw(&sampling,&base,&table)`. Its mutable encryptor borrows
the key and owns an ephemeral workspace. The `_to` methods reuse caller
output. To erase ephemeral values and keep the allocation, import
`zeroize::Zeroize` and call `workspace_mut().zeroize()`. The workspace also
erases its values on drop. See the [public encryptor contract](src/public_key/encryption.rs)
for checked layouts and caller-owned input and table requirements.

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

See the [phase guide](../../guides/development/rns-phase-conventions.md) for
the explicit bridge to BFV's `[c0,c1]` and `c0+c1*s` convention.

## Parameter composition

[`CrtGlweEncryptionParameters`](src/parameter/core.rs) owns layout and sampling
precomputation. Each signed error coefficient is sampled once and lifted to
every limb. Secret and noise support must fit every `q_i`, and fixed weights
refer to the complete `kN` secret. Recovery bounds, compatible NTT tables and
security parameters are separate obligations.

[`CrtGlevParameters`](src/parameter/gadget.rs) owns the gadget decomposition
for the ordered basis `Q`. Its basis must use the fixed limb width of `Q`
and a radix below every `q_i`. Bind sampling separately so each key role can
use its intended noise law.

## Evaluation resources

Use `try_bind_gadget(&gadget,&sampling,&table)` to prepare a secret
`DcrtGlevEncryptor` or public `DcrtGgswEncryptor`. GLev has distinct CRT and
DCRT input methods. See [gadget encryption](examples/gadget_encryption.rs)
for GGSW monomial encryption with reusable output.

Evaluators borrow immutable keys, parameters and tables and own mutable scratch.
Bind the complete ordered basis, decomposition and table before evaluating.
Each worker uses its own evaluator. The caller supplies matching roots/order,
actual secret identity, and a suitable error budget.

| Evaluator | Input → output | Preparation |
| --- | --- | --- |
| `CrtGlweAutoEvaluator` / `DcrtGlweAutoEvaluator` | CRT / DCRT under the original secret | Automorphism key, gadget and actual table |
| `DcrtGlweKeySwitchEvaluator` | CRT Q → DCRT Q | `try_new(&key,&gadget,&table)` |
| `HybridRnsGlweKeySwitchEvaluator` | DCRT Q → DCRT Q | `try_new(&key,&hybrid_rns,&qp_table)` |

[Hybrid key generation](src/key_switch/hybrid/generation.rs) checks the input
secret layout, both polynomial lengths, the ordered Q basis and QP table, and
the sampler's error magnitude bound against every QP modulus. The caller ensures
every signed coefficient in both secrets has magnitude below each QP modulus,
including for imported keys. See the
[bounded lift](src/secret_key/dcrt/conversion.rs) and
[Hybrid RNS contracts](../primus_rns/README.md#hybrid-rns).

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

Reverse trace uses division by two modulo Q. Its switching error can occupy
nonconstant coefficients. Supported expansion requires the caller to establish
that the plaintext degree is below the requested count. See
[reverse trace](src/dcrt/rev_trace.rs),
[CRT expansion](src/crt/expand_coeff/evaluator.rs), and
[DCRT expansion](src/dcrt/expand_coeff/evaluator.rs) for normalization and error
contracts. Parallel expansion uses the caller's Rayon pool and a positive
`worker_count` scratch budget.

## Ordinary RLWE parameter preparation

[`rlwe_parameters`](src/rlwe_parameters.rs) checks caller-selected u64 NTT
primes and provides bounded prime search. `security_input` inventories
secret-bearing domains and reports `NotEvaluated`. See the
[parameter and security guide](../../guides/development/ordinary-parameter-budgets.md)
for the scope of this inventory and independent security evaluation.

## Benchmarks

See the [raw phase benchmark](benches/raw_phase.rs).

```sh
cargo bench -p primus_glwe_rns --bench raw_phase
```

## Features and further reading

Default features are empty; RNS dependencies are enabled without a separate
`rns` switch. `simd` forwards nightly SIMD features. Runtime NTT intrinsic dispatch
is independent of that flag; disabling it does not force scalar NTT.

`parallel` enables [DCRT prefix scheduling](../primus_ntt/src/dcrt/mod.rs) in
shared GLev and Hybrid operations. It uses the caller's Rayon pool.

[Public API sources](src/lib.rs) · [Library usage guide](../../guides/development/README.md)
· [Testing and feature boundaries](../../guides/development/testing.md)
