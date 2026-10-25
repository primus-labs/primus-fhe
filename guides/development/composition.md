# Composing libraries and reusing workspaces

Start from the [library guide](README.md) to choose a crate. This guide covers the contracts that cross crate boundaries when combining lower-level APIs. For complete TFHE workflows, prefer the backend examples and context factories; they prepare the operation's encodings, paired material and workspace together. Numerical conditions specific to bootstrapping are in [bootstrapping contracts](bootstrapping-contracts.md).

## Establish the arithmetic domain

Choose the modulus, representation and decomposition before allocating ciphertexts. Use `NativeModulus` for the implicit machine-word modulus and `PowOf2Modulus` for an explicit power of two. NTT paths need suitable moduli and roots; `RingContext` / `FieldContext` describe arithmetic capabilities, not proofs of primality or invertibility. See [modulus choices](../../crates/primus_modulus/README.md) and [NTT construction](../../crates/primus_ntt/README.md).

Reuse checked [`primus_shape::PolyLength`](../../crates/primus_shape/README.md), `LweDimension`, `GlweDimension` and decomposition values when constructing parameters, sizes and tables. `GlweSize`, `GadgetSize` and their RNS counterparts describe complete ciphertext layouts; a matching size does not establish a modulus, basis or secret identity. The [lattice layout guide](../../crates/primus_lattice/README.md#storage-and-layout) describes these sizes.

| Representation | Pairing to preserve |
| --- | --- |
| Coefficient polynomial | N coefficients in the same negacyclic ring, with the method's canonical or wider residue range |
| NTT polynomial | N values with matching modulus, roots, evaluation order and normalization; lazy output is not automatically canonical input |
| Fourier polynomial | N/2 complex values with the same transform convention and table; torus and signed-integer transforms have different scaling |
| CRT / DCRT polynomial | N coefficients per modulus in the same ordered basis; DCRT also requires matching NTT conventions for every limb |

Use [NTT](../../crates/primus_ntt/README.md), [FFT](../../crates/primus_fft/README.md) and [RNS](../../crates/primus_rns/README.md) conversion APIs rather than reinterpreting a buffer. CRT/DCRT storage is modulus-major; batched big integers instead group the fixed-width limbs of each value. Equal products of moduli do not imply equal layouts. Source RNS residues must be canonical unless the selected operation documents a wider range.

Import and conversion boundaries also distinguish signed secrets from residues. Preserve the source modulus when lifting a secret into another ring; a residue such as q-1 represents -1, not a large positive coefficient. Owning secret types retain modulus metadata that raw views can erase. Even owning metadata does not prove that independently generated keys use the same actual secret or transform convention. See the [GLWE](../../crates/primus_glwe/README.md) and [NTRU](../../crates/primus_ntru/README.md) secret-conversion contracts.

## Borrow and traverse complete objects

`Polynomial::new(storage)` and analogous ciphertext wrappers move their container or borrow. `as_view()` / `as_mut_view()` preserve the representation type while borrowing; `into_inner()` returns the original storage without copying. None of these operations transforms coefficients or validates their mathematical domain. An operation consuming a mutable view can still modify the caller's buffer.

Raw wrappers do not carry an independent polynomial length. A flat batch must be traversed as complete objects, not passed to a single-polynomial operation as one oversized polynomial. Prefer the semantic iterators from [primus_poly](../../crates/primus_poly/README.md) and [primus_lattice](../../crates/primus_lattice/README.md):

| Data | Traversal |
| --- | --- |
| Coefficient / NTT / Fourier polynomials | `PolynomialIter`, `NttPolynomialIter`, `FourierPolynomialIter`, with their corresponding element strides |
| CRT / DCRT polynomials | `CrtPolynomialIter`, `DcrtPolynomialIter`, using the complete N × modulus-count stride |
| NTRU, NLEV and NGSW ciphertexts | `NtruIter`, `NlevIter`, `NgswIter`, using one complete ciphertext's length |
| GLWE, GLev and GGSW ciphertexts | `GlweIter`, `GlevIter`, `GgswIter`, using ciphertext lengths from their size descriptors |
| Gadget rows and GLWE components | Nested `iter_glev()`, `iter_glwe()` and `iter_poly()`; transformed variants retain the corresponding representation |

Iterators omit incomplete trailing objects, and `zip` stops at the shorter input. Validate complete lengths and matching counts at the boundary that accepts a batch. This matters even when the iterator itself is safe. A short final tile may contain fewer complete ciphertexts; it must not contain a truncated ciphertext. Individual methods' `# Panics` and `# Correctness` sections distinguish enforced checks from caller obligations.

## Keep messages, encoded values and phases separate

For LWE, single-modulus GLWE and NTRU, the ordinary flow is:

```text
message --codec + embedding--> encoded coefficients
        --encryption---------> ciphertext
        --phase extraction---> coefficient phase --codec--> message
```

`encrypt_message*` / `decrypt_message*` handle messages; `encrypt_encoded*` and `decrypt_phase*` expose the lower-level boundary. Message encryption explicitly chooses `PlaintextEmbedding`. For diagnostics, compare the phase with the encoding of the **expected message** using [phase-error helpers](../../crates/primus_encoding/README.md#phase-error-diagnostics). Re-encoding the decoded message can hide a wrong result. NTT/Fourier data is not a coefficient phase. Independent LWE batches and shared-mask packed messages also have different layouts; see [LWE batching](../../crates/primus_lwe/README.md#independent-batches-and-packed-messages).

Ordinary GLWE/NTRU parameters combine encryption parameters with a message codec. GLev/GGSW and NLev/NGSW encryption instead uses gadget weights and needs no ordinary message codec. Derive gadget parameters from existing ordinary parameters when appropriate, or use the documented component constructors for independently prepared parts. Sharing immutable sampler or RNS-base precomputations does not share secret coefficients, random-generator state or mutable workspace. Distinct key-noise roles may require distinct encryption parameters.

Match encryption to the compiled input domain and decoding to the output domain. Input and output message moduli may differ; feeding a result into another operation requires its encoding to fit that next input domain. TFHE factories supply these choices for their configured operation; manual composition must preserve them explicitly. In particular, Scaled MVB output is not automatically Rounded PBS input. See [TFHE encoding choices](../../crates/primus_tfhe/README.md#choosing-the-output-encoding).

RNS BFV uses its own scaling and recovery workflow: `encrypt_plaintext_crt_to` takes unscaled CRT lifts, so passing already-scaled codec output would apply the scale twice. `CrtGlweParameters` checks the codec's recovery bound using the noise sampler's maximum magnitude for fresh private-key encryption. Public-key encryption and evaluated ciphertexts need bounds for their complete phase error. Follow the [RNS GLWE encoding guide](../../crates/primus_glwe_rns/README.md#encoding-and-representation), rather than copying the single-modulus flow unchanged.

## Bind material before evaluation

Create contexts, tables, keys, programs and evaluators before repeated online calls. Prefer paired key generation and operation factories; explicit assembly must pair source/target secrets, moduli, layouts, bases and representations. Numerical metadata checks cannot establish actual secret identity, and a successful constructor does not certify a joint noise or security budget. Report construction errors through their `source()` chain to retain both the failed operation and its underlying cause.

Client secrets stay with the client. Evaluation/public keys and request ciphertexts can be supplied to the server; public parameters and LUTs can be prepared by either side. The server prepares and reuses its evaluators and outputs. Sharing a context does not make independently generated keys interchangeable.

For advanced TFHE composition, `ServerKey` carries BR/KS material; `CircuitBootstrapServerKey` combines it with the circuit key. Ordinary PBS owns its full return path, whereas CBS/one-hot produces ring or gadget ciphertexts and can use resources without ordinary return scratch. GLWE KS→BR still needs its input KS during CBS. See the [GLWE](../../crates/primus_tfhe_glwe/README.md) and [NTRU](../../crates/primus_tfhe_ntru/README.md) family workflows and [ciphertext domains](bootstrapping-contracts.md#ciphertext-domains-and-return).

## Reusing workspaces

| Role | Meaning |
| --- | --- |
| `Workspace` | Reusable temporary storage and its shape; borrowed groups may use `WorkspaceRefMut` |
| `Context` | Prepared parameters and arithmetic/transform environment; `RingContext` / `FieldContext` remain capability traits |
| `Resources` | Borrowed material/environment combined with matching owned buffers, as in `BootstrapResources` |
| `Evaluator` / `Engine` | An operation using owned or borrowed resources, as in PBS evaluators and `FftEngine` |

Allocate scratch outside the repeated operation and obey each method's overwrite/accumulate contract. Do not clear buffers merely because they contain a previous result, or assume an accumulating operation initializes its output. Workspace shape alone does not bind the basis, modulus, secret or transform table. GLWE external-product `with_rebound` temporarily changes gadget depth with unchanged GLWE geometry, restoring the original layout on return or unwind; changing geometry uses the separate resizing API and may allocate. See [lattice workspaces](../../crates/primus_lattice/README.md#correctness-and-workspace-contracts).

Serial CBS/one-hot and other operations can borrow compatible TFHE resources between calls. Preserve the context and BR-key pairing when borrowing resources from an ordinary PBS evaluator: its retained return material still depends on that pairing. A Fourier engine must remain paired with its table. Keep owners alive for borrowed bindings, and give concurrent requests independent mutable state. Equal scratch lengths alone neither justify merging buffers nor establish a performance gain; live data dependencies and complete-request measurements decide reuse.

Do not treat an error or panic as a transaction rollback. Some operations validate before writing; others can leave partial outputs. Only rely on a recovery or retry guarantee when the API documents it. RNS parallel coefficient expansion, for example, needs a sufficiently sized preallocated workspace pool; an undersized pool can fail after partial output writes. See [RNS evaluation resources](../../crates/primus_glwe_rns/README.md#evaluation-resources).

### NTRU return streams

The coefficient-domain `primus_ntru::LweReturnEvaluator` borrows a return key and target q independently of NTT/FFT scratch. Prepare scalar and/or batch workspace as needed. Shared-input returns preserve arbitrary/repeated indices (`return_many_at_to`) or select a prefix (`return_prefix_to`), reusing one Q→q conversion; a stream converts each different source and retains only its extracted LWE. Their numerical order is described in [return contracts](bootstrapping-contracts.md#ciphertext-domains-and-return).

For an independent stream, call `begin_batch`, append samples in order with `append_at`, then submit exactly the filled prefix with `return_batch_to`. Successful submission invalidates the prefix; `discard_batch` or a new `begin_batch` discards it. Documented input/index and output-count/dimension rejections retain the prefix. Shared-input returns reject an active stream, while separate scalar workspace remains usable.

An append retains no source borrow, so BR/one-hot/product buffers may be reused before submission. All appends and submission must use the same actual secrets and Q/q: the workspace tracks valid slots, not key identity. Full protocol and output contracts are on [LweReturnEvaluator](../../crates/primus_ntru/src/key_switch/lwe/evaluator.rs).

## Storage and erasure

Fixed length, extra alignment and reuse are separate choices. `Box<[T]>` expresses fixed storage; `Vec<T>` supports growth. Use `ABox` / `AVec` when the consumer needs stronger alignment or measurements support it. With `primus_data/aligned-vec`, aligned containers implement `Data` / `DataMut`, but not `DataOwned`: allocate with explicit alignment, then wrap the container. See [storage capabilities](../../crates/primus_data/README.md).

An aligned base does not align every offset view, especially LWE rows with n+1 elements. Aligning a vector of key objects does not align their separate coefficient allocations. Preserve backend-specific allocation and erasure contracts; storage type alone is not evidence of speed. Choose buffer reuse with complete-request measurements; equal shapes and fewer allocations do not imply lower latency.

Read each type's zeroization contract before reuse. An erased key may have lost its length and be unusable; a workspace may retain its shape and allocation. Do not infer one behavior from the other.
