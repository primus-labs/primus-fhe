# primus_glwe_rns

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE encryption and evaluation over an ordered RNS basis, with CRT coefficient and DCRT NTT representations. It supplies codec-free phase encryption, gadget products, automorphism, trace, expansion and key switching. BFV message scaling, coefficient encryption and recovery belong to [primus_bfv](../primus_bfv/README.md).

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

Scheme implementations can fuse encoding into sampled coefficient noise with secret `encrypt_with_body_to` or public `encrypt_with_components_to`. Callbacks run before each affected component's sole NTT; the latter visits masks then body. The primitive allocates no buffer, while callback costs and canonical-residue/message/noise semantics belong to the caller. Ordinary BFV callers use `primus_bfv` directly.

## BFV message workflow

Use [primus_bfv](../primus_bfv/README.md) for rank-one u64 BFV parameters, unsigned/centered coefficient encryption, unscaled CRT plaintext encryption and decoding. Raw methods in this crate accept an already-encoded phase and never apply BFV delta. Gadget messages instead use their own decomposition weights.

## Prepared public encryption

Generate `DcrtGlwePublicKey` once from codec-free sampling parameters. Each binding below borrows the key and prepares one owned ephemeral workspace; encryption methods take `&mut self`:

| Binding | Prepared encryptor | Input |
| --- | --- | --- |
| `public_key.try_bind_raw(&domain)` | `DcrtGlweRawPublicKeyEncryptor` | Already-encoded CRT phase, or zero; no implicit scale |
| `public_key.try_bind_gadget(&gadget_domain)` | `DcrtGgswEncryptor` | Monomial coefficient residues and degree; applies gadget weights |

Reuse caller output with `encrypt_encoded_crt_to`, `encrypt_zeros_to` or `encrypt_monomial_ggsw_to`. Prepared `_to` calls overwrite the complete DCRT output without allocating. The allocating `encrypt_monomial_ggsw` convenience allocates only its result. Encoded CRT phase or gadget-monomial injection is fused with coefficient noise before the component's existing NTT; these inputs are not DCRT polynomials.

`workspace()` reports the retained scratch geometry. `workspace_mut().zeroize()` explicitly erases ephemeral values while retaining the allocation for reuse; import `zeroize::Zeroize` to call it. Scratch is also erased on drop. Its last values otherwise remain until overwritten. Caller-owned ciphertext outputs are separate and are not erased by workspace cleanup. Output, residue-count, degree and workspace-shape checks precede sampling and writes; canonical residues and the intended key/NTT domain remain caller contracts.

The [public encryption example](examples/public_encryption.rs) composes raw and gadget modes, reuses outputs and explicitly erases scratch:

```sh
cargo run -p primus_glwe_rns --example public_encryption
```

## Encoding and representation

Raw encryption accepts canonical CRT residues directly; it does not interpret a plaintext modulus or apply message scaling. Its phase output is DCRT. Inverse transformation and message recovery remain explicit operations. GLev applies gadget weights to CRT or DCRT inputs through distinct methods.

With m moduli, ordinary ciphertext storage contains `(k+1)*m*N` elements in `[component][modulus][coefficient/evaluation]` order. Gadget storage adds outer row/level dimensions. CRT and DCRT share a shape but have different arithmetic. Use `RnsGlweSize` / `RnsGadgetSize` and semantic iterators; keep the modulus order throughout. See [ciphertext layouts](../primus_lattice/README.md#storage-and-layout).

## Parameter composition

| Parameters | Purpose |
| --- | --- |
| `CrtGlweEncryptionParameters` | Layout, ordered moduli and samplers; no plaintext codec |
| `DcrtGlweDomain` | Checked codec-free binding of sampling parameters, ordered RNS base and DCRT table |
| `CrtGlevParameters` | Encryption parameters and gadget decomposition under product modulus Q; no BFV scaling |

Use `GlweDimension` and [PolyLength](../primus_shape/README.md#polynomial-length) for dimensions and ring length, and `DecompositionBaseLog` / `DecompositionLevelCount` for decomposition. Reuse these checked values across parameters, sizes and tables. Fixed secret weights apply to the complete kN signed key, not separately per polynomial or RNS limb. Secret and noise magnitudes must fit below every q_i. Noise is sampled once per coefficient as an integer and lifted consistently across all RNS limbs. `CrtGlweEncryptionParametersError` reports codec-free domain/sampling failures. BFV parameter and recovery errors are owned by `primus_bfv`.

Use [`CrtGlevParameters::try_from_parts`](src/parameter/gadget.rs) to bind shared encryption parameters, an ordered base and a matching decomposition basis. This requires no t or gamma. BFV consumers may derive these parameters with `BfvParameters::try_gadget_parameters` in the scheme crate. The decomposition basis must match Q and its fixed-width limb representation, with radix strictly smaller than every q_i. Prepare separate encryption parameters when key roles require different noise distributions.

Raw parameter construction establishes layout and sampling support, not a message-recovery bound, NTT availability or a security level. Public-key and evaluated phase errors require bounds for the complete operation.

## Evaluation resources

Bind raw secret/public keys with `try_bind_raw(&domain)`. For gadget work, construct `DcrtGadgetDomain::try_new(&gadget, &table)` and use `try_bind_gadget(&domain)`: a secret key returns `DcrtGlevEncryptor`, while a public key returns `DcrtGgswEncryptor`. GLev's `encrypt_crt_to` / `encrypt_dcrt_to` accept coefficient / NTT messages and apply gadget weights. GGSW's `encrypt_monomial_ggsw` / `encrypt_monomial_ggsw_to` allocate / reuse output.

The client generates public/evaluation keys and supplies them to the server. Public-key and key-switch generation use codec-free `encryption_parameters()`. Construct an evaluator once from its key and domain, then reuse its owned scratch for online calls. Binding checks resource layouts, ordered bases and applicable decomposition parameters. Evaluator and prepared public/gadget encryption methods check complete input/output lengths before writes. Canonical residues, NTT roots/order, secret identity and sufficient noise margins remain caller obligations.

Prepare automorphism material with `DcrtGlweAutoKey::new(&gadget_domain, exponent, &key, &mut rng)`, then bind `DcrtGlweAutoEvaluator::try_new(&auto_key, &gadget_domain)` once and reuse its output. Gadget construction and raw/public output reuse are demonstrated in the examples linked above.

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

Expansion has no extra count factor. Partial expansion retains higher **plaintext** coefficients in their residue classes; Relect's block-factor accumulator uses this behavior. Supported expansion instead requires the protocol or caller to guarantee that the plaintext degree is less than k, which the encrypted input cannot establish at runtime. It normalizes with `next_power_of_two(k)^-1 mod Q` and evaluates k−1 automorphisms, doubling already-scalar leaves instead of evaluating padded branches. This doubles their existing phase error as well; the operation count is not a noise or security bound. Ciphertext/noise tails need not vanish, and ring length remains N. Full layouts and representation requirements are documented on the [CRT](src/crt/expand_coeff/evaluator.rs) and [DCRT](src/dcrt/expand_coeff/evaluator.rs) evaluators.

Use `*GlweExpandCoeffEvaluator::new(&key, &domain)` for serial expansion or `*GlweExpandCoeffParallelEvaluator::new(&key, &domain, worker_count)` for a preallocated scratch budget. Serial evaluation needs one workspace; parallel evaluation reserves `worker_count` workspaces. Repeated calls reuse arithmetic scratch.

Parallel calls use the caller's Rayon pool and divide each level into at most `worker_count` scratch-bearing jobs. This positive budget may be smaller or larger than the pool's thread count; no inner thread pool is created. Initialize the caller pool before evaluation and borrow the evaluator mutably. Complete input/output lengths and counts are checked before writes. Complete numerical and resource contracts are on the evaluator methods.

## Features and further reading

Default features are empty. `simd` forwards nightly SIMD support to arithmetic dependencies. This crate enables the RNS features it needs without a separate `rns` switch.

[Public API sources](src/lib.rs) · [RNS bases and conversion](../primus_rns/README.md) · [Library usage guide](../../guides/development/README.md) · [Testing guide](../../guides/development/testing.md)
