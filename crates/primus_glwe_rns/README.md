# primus_glwe_rns

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE encryption and evaluation over an ordered RNS basis, with CRT coefficient and DCRT NTT representations. It supplies codec-free phase encryption, BFV coefficient encryption, gadget products, automorphism, trace, expansion and key switching as building blocks, not a complete BFV/BGV/CKKS scheme.

## Codec-free raw workflow

Use raw encryption when the caller owns the encoded phase. It needs no plaintext modulus, BFV scale, decoding modulus gamma or gadget basis:

1. Prepare an ordered `RNSBase`, a matching `DcrtTable` and `RnsGlweSize`.
2. Construct `CrtGlweEncryptionParameters`. `try_new` selects Gaussian noise; `try_with_error_distribution` also accepts exact `ErrorDistribution::CenteredBinomial { eta }` from `primus_distr`. Use eta=1 for CBD1 and eta=21 for CBD21. Gaussian noise with a similar standard deviation is a different distribution.
3. Bind these resources with `DcrtGlweDomain::try_new(&parameters, &base, &table)`, convert a signed `GlweSecretKey` to DCRT, then call `key.try_bind_raw(&domain)` once.
4. Reuse caller-owned ciphertext and polynomial outputs with the returned `DcrtGlweRawSecretKeyContext`. The binding borrows resources without cloning the key; raw operations allocate no scratch.

| Raw context method | Result |
| --- | --- |
| `encrypt_encoded_crt_to` | Adds the supplied canonical CRT coefficients directly to coefficient noise; output DCRT phase is encoded input plus noise, with no implicit scale |
| `encrypt_zeros_to` | Fresh zero encryption in the same DCRT layout |
| `phase_to` | Full DCRT phase `b - sum(a_i*s_i)` |
| `partial_phase_to` | DCRT contribution `-sum(a_i*s_i)`, without the body b |

Sum partial phases under additive secret shares and add b **exactly once**. One full phase plus the other partial phases gives the same result. These are raw arithmetic operations: opening privacy noise, authorized outputs and one-use/retry rules belong to the calling protocol. Phase output remains in NTT form; inverse transformation and any decoding are explicit caller operations.

Domain/key binding checks geometry and ordered moduli. Raw methods reject incorrect complete buffer lengths before writes or sampling; canonical residues, transform identity, actual secret identity and message semantics remain caller obligations. The [raw encryption example](examples/raw_encryption.rs) shows a complete u64 workflow, storage reuse and the body/share relation:

```sh
cargo run -p primus_glwe_rns --example raw_encryption
```

## BFV coefficient workflow

1. Choose ordered, pairwise-coprime NTT primes and construct one `DcrtTable`. Each prime must satisfy the [NTT constraints](../primus_ntt/README.md#construction-constraints).
2. Construct `CrtGlweParameters` with dimension k, polynomial length N, plaintext modulus t, auxiliary decoding modulus gamma, ordered ciphertext moduli, secret distribution and noise. Use `try_new` to handle invalid configurations; its [`BfvRnsCodec`](../primus_encoding/README.md#bfv-rns) supplies scaling and recovery checks.
3. Generate a signed coefficient `GlweSecretKey` and convert it with `DcrtGlweSecretKey::from_coeff_secret_key`. Bind it once with `try_bind(&parameters, &table)`, then use the returned `DcrtGlweSecretKeyContext`.
4. Allocate ciphertexts using parameter length accessors. Reuse output and `DcrtGlweDecryptWorkspace`; `decrypt_to` also reuses caller plaintext output.

The small parameters below demonstrate coefficient encryption and storage reuse, not security. The snippet requires `primus_glwe_rns`, `primus_lattice`, `primus_modulus`, `primus_ntt`, `primus_poly`, `primus_shape` and `rand` as direct dependencies:

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

## Prepared public encryption

Generate `DcrtGlwePublicKey` once from codec-free sampling parameters. Each binding below borrows the key and prepares one owned ephemeral workspace; encryption methods take `&mut self`:

| Binding | Prepared encryptor | Input |
| --- | --- | --- |
| `public_key.try_bind_raw(&domain)` | `DcrtGlweRawPublicKeyEncryptor` | Already-encoded CRT phase, or zero; no implicit scale |
| `public_key.try_bind(&parameters, &table)` | `DcrtGlwePublicKeyContext` | Unscaled CRT plaintext; applies BFV delta |
| `public_key.try_bind_gadget(&gadget_domain)` | `DcrtGgswEncryptor` | Monomial coefficient residues and degree; applies gadget weights |

Reuse caller output with `encrypt_encoded_crt_to`, `encrypt_zeros_to`, `encrypt_plaintext_crt_to` or `encrypt_monomial_ggsw_to`. Prepared `_to` calls overwrite the complete DCRT output without allocating. The allocating `encrypt_plaintext_crt` and `encrypt_monomial_ggsw` conveniences allocate only their result. CRT message or gadget-monomial injection is fused with coefficient noise before the component's existing NTT; these inputs are not DCRT polynomials.

`workspace()` reports the retained scratch geometry. `workspace_mut().zeroize()` explicitly erases ephemeral values while retaining the allocation for reuse; import `zeroize::Zeroize` to call it. Scratch is also erased on drop. Its last values otherwise remain until overwritten. Caller-owned ciphertext outputs are separate and are not erased by workspace cleanup. Output, residue-count, degree and workspace-shape checks precede sampling and writes; canonical residues and the intended key/NTT domain remain caller contracts.

The [public encryption example](examples/public_encryption.rs) composes raw, BFV and gadget modes, reuses outputs and explicitly erases scratch:

```sh
cargo run -p primus_glwe_rns --example public_encryption
```

## Encoding and representation

Let `Q = product_i q_i`. BFV message methods below apply scaling `floor(Q/t)`; raw encoded-phase encryption applies none, while gadget encryption uses its own basis.

| BFV secret-key context method | Input or result |
| --- | --- |
| `encrypt_to` / `encrypt_centered_to` | N canonical messages in `[0,t)`, using unsigned / centered lifting |
| `encrypt_plaintext_crt_to` | Unscaled plaintext lifts reduced into each `[0,q_i)`; applies BFV scaling |
| `encrypt_zeros_to` | Zero encryption |
| `phase_to` | DCRT phase, without coefficient recovery or decoding |
| `decrypt` / `decrypt_to` | Decoded coefficient polynomial; allocate / reuse plaintext output |

Encryption overwrites DCRT output. **Do not pass already-scaled codec output to `encrypt_plaintext_crt_to`**: it would apply the scale twice. The public context's method accepts the same unscaled CRT lifts; its noise includes additional public-key contributions.

With m moduli, ordinary ciphertext storage contains `(k+1)*m*N` elements in `[component][modulus][coefficient/evaluation]` order. Gadget storage adds outer row/level dimensions. CRT and DCRT share a shape but have different arithmetic. Use `RnsGlweSize` / `RnsGadgetSize` and semantic iterators; keep the modulus order throughout. See [ciphertext layouts](../primus_lattice/README.md#storage-and-layout).

## Parameter composition

| Parameters | Purpose |
| --- | --- |
| `CrtGlweParameters` | Ordinary BFV encryption/decryption, including t, gamma and recovery conditions |
| `CrtGlweEncryptionParameters` | Layout, ordered moduli and samplers; no plaintext codec |
| `DcrtGlweDomain` | Checked codec-free binding of sampling parameters, ordered RNS base and DCRT table |
| `CrtGlevParameters` | Encryption parameters and gadget decomposition under product modulus Q; no BFV scaling |

Use `GlweDimension` and [PolyLength](../primus_shape/README.md#polynomial-length) for dimensions and ring length, and `DecompositionBaseLog` / `DecompositionLevelCount` for decomposition. Reuse these checked values across parameters, sizes and tables. Fixed secret weights apply to the complete kN signed key, not separately per polynomial or RNS limb. Secret and noise magnitudes must fit below every q_i. Noise is sampled once per coefficient as an integer and lifted consistently across all RNS limbs. `CrtGlweEncryptionParametersError` reports codec-free domain/sampling failures; BFV recovery errors remain on `CrtGlweParametersError`.

Given ordinary parameters, `CrtGlevParameters::try_with_glwe_params` derives gadget parameters in the same ordered basis. Gadget-only construction needs no t or gamma; see [`CrtGlevParameters::try_from_parts`](src/parameter/gadget.rs). The decomposition basis must match Q and its fixed-width limb representation, with radix strictly smaller than every q_i. Prepare separate encryption parameters when key roles require different noise distributions.

Ordinary parameter construction uses the sampler's maximum noise magnitude with `BfvRnsCodec::validate_noise_bound`. The unsigned-lifting check also covers centered lifting and establishes recovery for **fresh private-key encryption**; insufficient margin returns `CrtGlweParametersError::Encoding`. Public-key encryption and homomorphic evaluation need bounds on their complete phase noise. Construction does not establish NTT availability or a security level.

## Evaluation resources

Bind ordinary secret/public keys with `try_bind(&parameters, &table)`. For gadget work, construct `DcrtGadgetDomain::try_new(&gadget, &table)` and use `try_bind_gadget(&domain)`: a secret key returns `DcrtGlevEncryptor`, while a public key returns `DcrtGgswEncryptor`. GLev's `encrypt_crt_to` / `encrypt_dcrt_to` accept coefficient / NTT messages and apply gadget weights. GGSW's `encrypt_monomial_ggsw` / `encrypt_monomial_ggsw_to` allocate / reuse output.

The client generates public/evaluation keys and supplies them to the server. Public-key and key-switch generation use codec-free `encryption_parameters()`. Construct an evaluator once from its key and domain, then reuse its owned scratch for online calls. Binding checks resource layouts, ordered bases and applicable decomposition parameters. Evaluator and prepared public/gadget encryption methods check complete input/output lengths before writes. Canonical residues, NTT roots/order, secret identity and sufficient noise margins remain caller obligations.

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

| Key-switch evaluator | Input → output | Domain |
| --- | --- | --- |
| `DcrtGlweKeySwitchEvaluator` | CRT Q → DCRT Q | `DcrtGadgetDomain` over ordered Q with matching gadget layout and radix |
| `HybridRnsGlweKeySwitchEvaluator` | DCRT Q → DCRT Q | `HybridRnsKeySwitchDomain` over ordered QP with matching N, Q/P boundary and partition width |

Both provide `try_new(&key, &domain)` and online `key_switch_to(&input, &mut output)`. Hybrid key generation takes its key noise from the input encryption parameters and checks its support against every QP modulus; both secrets' magnitudes must also fit every QP modulus. Partitioning and ModUp/ModDown contracts are in [`primus_rns`](../primus_rns/README.md#hybrid-rns).

## Trace and coefficient expansion

These evaluators borrow the key and gadget domain and own reusable scratch. Inputs remain unchanged; outputs and scratch are overwritten. Target messages below omit evaluation error.

| Evaluator and method | Target message |
| --- | --- |
| `CrtGlweTraceEvaluator` / `DcrtGlweTraceEvaluator`, `trace_to` | Constant `N*m[0]` |
| `DcrtGlweRevTraceEvaluator`, `trace_to` | Constant `m[0]` |
| CRT/DCRT `expand_coefficients_to` | Exactly N outputs, output j targeting constant `m[j]` |
| CRT/DCRT `expand_partial_coefficients_to` | Power-of-two count d in `1..=N`; output j targets `sum_k m[j+k*d] * X^(k*d)` |
| CRT/DCRT `expand_supported_coefficients_to` | Any count k in `1..=N`; output j targets constant `m[j]` when plaintext degree is less than k |

Reverse trace multiplies by `2^-1 mod q_i` before each automorphism/addition. It preserves Q and ring length; this is modular division, not modulus switching or rounded halving. The full sequence projects input message and input error onto the constant coefficient, but later key-switch errors may survive at nonconstant positions. The native-torus variance bound does not follow from the absence of rounding; see the [phase and error contract](src/dcrt/rev_trace.rs).

Expansion has no extra count factor. Partial expansion retains higher **plaintext** coefficients in their residue classes; Relect's block-factor accumulator uses this behavior. Supported expansion instead requires the protocol or caller to guarantee that the plaintext degree is less than k, which the encrypted input cannot establish at runtime. It normalizes with `next_power_of_two(k)^-1 mod Q` and evaluates k−1 automorphisms, doubling already-scalar leaves instead of evaluating padded branches. Ciphertext/noise tails need not vanish, and ring length remains N. Full layouts and representation requirements are documented on the [CRT](src/crt/expand_coeff/evaluator.rs) and [DCRT](src/dcrt/expand_coeff/evaluator.rs) evaluators.

Use `*GlweExpandCoeffEvaluator::new(&key, &domain)` for serial expansion or `*GlweExpandCoeffParallelEvaluator::new(&key, &domain, worker_count)` for a preallocated scratch budget. Serial evaluation needs one workspace; parallel evaluation reserves `worker_count` workspaces. Repeated calls reuse arithmetic scratch.

Parallel calls use the caller's Rayon pool and divide each level into at most `worker_count` scratch-bearing jobs. This positive budget may be smaller or larger than the pool's thread count; no inner thread pool is created. Initialize the caller pool before evaluation and borrow the evaluator mutably. Complete input/output lengths and counts are checked before writes. Complete numerical and resource contracts are on the evaluator methods.

## Features and further reading

Default features are empty. `simd` forwards nightly SIMD support to arithmetic dependencies. This crate enables the RNS features it needs without a separate `rns` switch.

[Public API sources](src/lib.rs) · [RNS bases and conversion](../primus_rns/README.md) · [Library usage guide](../../guides/development/README.md) · [Testing guide](../../guides/development/testing.md)
