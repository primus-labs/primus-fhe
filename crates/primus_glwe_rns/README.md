# primus_glwe_rns

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE encryption and evaluation over an ordered RNS basis, with CRT coefficient and DCRT NTT representations. It supplies BFV-scaled encryption, gadget products, automorphism, trace, expansion and key switching as building blocks, not a complete BFV/BGV/CKKS scheme.

## Recommended workflow

1. Choose ordered, pairwise-coprime NTT primes and construct one `DcrtTable`. Each prime must satisfy the [NTT constraints](../primus_ntt/README.md#construction-constraints).
2. Construct `CrtGlweParameters` with dimension k, polynomial length N, plaintext modulus t, auxiliary decoding modulus gamma, ordered ciphertext moduli, secret distribution and noise. Use `try_new` to handle invalid configurations; its [`BfvRnsCodec`](../primus_encoding/README.md#bfv-rns) supplies scaling and recovery checks.
3. Generate a signed coefficient `GlweSecretKey` and convert it with `DcrtGlweSecretKey::from_coeff_secret_key`. Bind it once with `try_bind(&parameters, &table)`, then use the returned `DcrtGlweSecretKeyContext`.
4. Allocate ciphertexts using parameter length accessors. Reuse output and `DcrtGlweDecryptWorkspace`; `decrypt_to` also reuses caller plaintext output.

The small parameters below demonstrate coefficient encryption and storage reuse, not security. The snippet requires `primus_glwe_rns`, `primus_lattice`, `primus_modulus`, `primus_ntt`, `primus_poly` and `rand` as direct dependencies:

```rust
use primus_glwe_rns::{
    CrtGlweParameters, DcrtGlweCiphertext, DcrtGlweDecryptWorkspace,
    DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::Polynomial;
use primus_shape::PolyLength;

let moduli = [998_244_353u32, 1_004_535_809].map(BarrettModulus::new);
let poly_length = PolyLength::new(32);
let table = UintDcrtTable::new(poly_length, &moduli).unwrap();
let parameters = CrtGlweParameters::new(
    primus_lattice::GlweDimension::new(2), poly_length, BarrettModulus::new(17), BarrettModulus::new(65_537),
    &moduli, SecretKeyDistr::UniformBinary, 3.2,
);
let mut rng = rand::rng();
let coefficient_key = GlweSecretKey::generate(
    parameters.size().glwe_size(), parameters.secret_key_sampler(), &mut rng,
);
let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
let mut ciphertext = DcrtGlweCiphertext::<Vec<u32>>::zero(parameters.rns_glwe_len());
let mut workspace = DcrtGlweDecryptWorkspace::new(parameters.size());
let message = Polynomial::new(vec![3u32; parameters.poly_length().get()]);

let context = key.try_bind(&parameters, &table).unwrap();
context.encrypt_to(&message, &mut ciphertext, &mut rng);
let decoded = context.decrypt(&ciphertext, &mut workspace);
assert_eq!(decoded.as_ref(), message.as_ref());
```

## Encoding and representation

Let `Q = product_i q_i`. Ordinary encryption applies BFV scaling `floor(Q/t)`; gadget encryption uses its own basis without BFV scaling.

| Secret-key context method | Input or result |
| --- | --- |
| `encrypt_to` / `encrypt_centered_to` | N canonical messages in `[0,t)`, using unsigned / centered lifting |
| `encrypt_plaintext_crt_to` | Unscaled plaintext lifts reduced into each `[0,q_i)`; applies BFV scaling |
| `encrypt_zeros_to` | Zero encryption |
| `phase_to` | DCRT phase, without coefficient recovery or decoding |
| `decrypt` / `decrypt_to` | Decoded coefficient polynomial; allocate / reuse plaintext output |

Encryption overwrites DCRT output. **Do not pass already-scaled codec output to `encrypt_plaintext_crt_to`**: it would apply the scale twice. `DcrtGlwePublicKeyContext::encrypt_plaintext_crt` allocates public encryption of the same unscaled CRT lifts; its noise includes additional public-key contributions.

With m moduli, ordinary ciphertext storage contains `(k+1)*m*N` elements in `[component][modulus][coefficient/evaluation]` order. Gadget storage adds outer row/level dimensions. CRT and DCRT share a shape but have different arithmetic. Use `RnsGlweSize` / `RnsGadgetSize` and semantic iterators; keep the modulus order throughout. See [ciphertext layouts](../primus_lattice/README.md#storage-and-layout).

## Parameter composition

| Parameters | Purpose |
| --- | --- |
| `CrtGlweParameters` | Ordinary BFV encryption/decryption, including t, gamma and recovery conditions |
| `CrtGlweEncryptionParameters` | Layout, ordered moduli and samplers; no plaintext codec |
| `CrtGlevParameters` | Encryption parameters and gadget decomposition under product modulus Q; no BFV scaling |

Use `GlweDimension` and [PolyLength](../primus_shape/README.md#polynomial-length) for dimensions and ring length, and `DecompositionBaseLog` / `DecompositionLevelCount` for decomposition. Reuse these checked values across parameters, sizes and tables. Fixed secret weights apply to the complete kN signed key, not separately per polynomial or RNS limb. Secret and noise magnitudes must fit below every q_i; noise deviation is in coefficient units.

Given ordinary parameters, `CrtGlevParameters::try_with_glwe_params` derives gadget parameters in the same ordered basis. Gadget-only construction needs no t or gamma; see [`CrtGlevParameters::try_from_parts`](src/parameter/gadget.rs). The decomposition basis must match Q and its fixed-width limb representation, with radix strictly smaller than every q_i. Prepare separate encryption parameters when key roles require different noise distributions.

Ordinary parameter construction uses the sampler's maximum noise magnitude with `BfvRnsCodec::validate_noise_bound`. The unsigned-lifting check also covers centered lifting and establishes recovery for **fresh private-key encryption**; insufficient margin returns `CrtGlweParametersError::Encoding`. Public-key encryption and homomorphic evaluation need bounds on their complete phase noise. Construction does not establish NTT availability or a security level.

## Evaluation resources

Bind ordinary secret/public keys with `try_bind(&parameters, &table)`. For gadget work, construct `DcrtGadgetDomain::try_new(&gadget, &table)` and use `try_bind_gadget(&domain)`: a secret key returns `DcrtGlevEncryptor`, while a public key returns `DcrtGgswEncryptor`. GLev's `encrypt_crt_to` / `encrypt_dcrt_to` accept coefficient / NTT messages and apply gadget weights. GGSW's `encrypt_monomial_ggsw` / `encrypt_monomial_ggsw_to` allocate / reuse output.

The client generates public/evaluation keys and supplies them to the server. Public-key and key-switch generation use codec-free `encryption_parameters()`. Construct an evaluator once from its key and domain, then reuse its owned scratch for online calls. Binding checks resource layouts, ordered bases and applicable decomposition parameters; input/output layouts, canonical residues, NTT roots/order, secret identity and sufficient noise margins remain caller obligations.

For example, continuing the encryption workflow above (also add `primus_decompose` as a dependency):

```rust
use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{CrtGlevParameters, DcrtGadgetDomain, DcrtGlweAutoEvaluator, DcrtGlweAutoKey};

let gadget = CrtGlevParameters::with_glwe_params(&parameters, DecompositionBaseLog::new(8), None);
let domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
let auto_key = DcrtGlweAutoKey::new(&domain, 3, &key, &mut rng);
let mut evaluator = DcrtGlweAutoEvaluator::try_new(&auto_key, &domain).unwrap();
let mut output = DcrtGlweCiphertext::<Vec<u32>>::zero(parameters.rns_glwe_len());
evaluator.automorphism_to(&ciphertext, &mut output);
```

`CrtGlweAutoEvaluator` uses coefficient ciphertexts; `DcrtGlweAutoEvaluator` uses NTT ciphertexts. Both evaluate under the original secret.

| Key-switch evaluator | Domain |
| --- | --- |
| `DcrtGlweKeySwitchEvaluator` | `DcrtGadgetDomain` over ordered Q with matching gadget layout and radix |
| `HybridRnsGlweKeySwitchEvaluator` | `HybridRnsKeySwitchDomain` over ordered QP with matching N, Q/P boundary and partition width |

Both provide `try_new(&key, &domain)` and online `key_switch_to(&input, &mut output)`. Hybrid key generation takes its key noise from the input encryption parameters and checks its support against every QP modulus; both secrets' magnitudes must also fit every QP modulus. Partitioning and ModUp/ModDown contracts are in [`primus_rns`](../primus_rns/README.md#hybrid-rns).

## Trace and coefficient expansion

These evaluators borrow the key and gadget domain and own reusable scratch. Inputs remain unchanged; outputs and scratch are overwritten. Target messages below omit evaluation error.

| Evaluator and method | Target message |
| --- | --- |
| `CrtGlweTraceEvaluator` / `DcrtGlweTraceEvaluator`, `trace_to` | Constant `N*m[0]` |
| `DcrtGlweRevTraceEvaluator`, `trace_to` | Constant `m[0]` |
| CRT/DCRT `expand_coefficients_to` | Exactly N outputs, output j targeting constant `m[j]` |
| CRT/DCRT `expand_partial_coefficients_to` | A power-of-two count in `1..=N`, targeting the first coefficients as constants when the message tail is zero |

Reverse trace multiplies by `2^-1 mod q_i` before each automorphism/addition. It preserves Q and ring length; this is modular division, not modulus switching or rounded halving. The full sequence projects input message and input error onto the constant coefficient, but later key-switch errors may survive at nonconstant positions. The native-torus variance bound does not follow from the absence of rounding; see the [phase and error contract](src/dcrt/rev_trace.rs).

Expansion has no extra count factor. For partial expansion to produce constants, **plaintext** coefficients beyond the requested prefix must be zero; otherwise they remain at higher powers of X. Ciphertext/noise tails need not vanish, and ring length remains N. Full layouts and representation requirements are documented on the [CRT](src/crt/expand_coeff/evaluator.rs) and [DCRT](src/dcrt/expand_coeff/evaluator.rs) evaluators.

Use `*GlweExpandCoeffEvaluator::new(&key, &domain)` for serial expansion or `*GlweExpandCoeffParallelEvaluator::new(&key, &domain, worker_count)` for a preallocated parallel pool. Serial evaluation needs one workspace; parallel evaluation reserves one per worker. Repeated calls reuse arithmetic scratch.

Parallel calls use Rayon. Initialize its pool before evaluation and choose a positive `worker_count` covering the maximum simultaneous workers; for a custom pool, use its `current_num_threads()`. Calls borrow the evaluator mutably. An undersized scratch pool can panic **after partial output writes**; complete usage conditions are on the evaluator methods.

## Features and further reading

Default features are empty. `simd` forwards nightly SIMD support to arithmetic dependencies. This crate enables the RNS features it needs without a separate `rns` switch.

[Public API sources](src/lib.rs) · [RNS bases and conversion](../primus_rns/README.md) · [Library usage guide](../../guides/development/README.md) · [Testing guide](../../guides/development/testing.md)
