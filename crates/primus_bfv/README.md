# primus_bfv

English | [简体中文](README.zh_CN.md)

BFV coefficient encryption, linear/plaintext evaluation and rounded modulus
switching with native components `[c0,c1]` and phase `c0+c1*s`. The rank-one
backend uses `u64` residues, `BarrettModulus<u64>` and `U64DcrtTable`; the product
Q may exceed 64 bits. Sharing secret storage with `primus_glwe_rns` preserves
the actual coefficient secret.

The crate owns BFV parameters, context, ciphertext/public-key semantics, clients
and evaluators. Ciphertext multiplication/relinearization and SIMD slots are not
provided. The coefficient codec remains in `primus_encoding`; arithmetic, NTTs,
samplers and secret storage are reused from lower layers.

## Coefficient workflow

Run the complete [leveled example](examples/leveled_coefficients.rs):

```sh
cargo run -p primus_bfv --example leveled_coefficients
```

1. Construct `BfvParameters::try_coefficients(N, t, &Q, secret_law, sigma)`.
   This uses the default decoder modulus `gamma=2^61-1`. Advanced callers can
   select gamma with `try_new`, or gamma and a Gaussian/CBD error law with
   `try_with_error_distribution`. Every constructor validates the codec's
   coprimality/recovery conditions; the convenience requires `t < gamma`.
2. Move the parameters into `BfvContext::try_new` for the highest level only,
   or `try_with_levels(parameters, level_count)` for a prefix chain. The count
   includes level zero: level 0 uses all Q primes and level `l` removes the last
   `l` primes. Only requested lower codecs are prepared.
3. Generate `BfvClient::generate(&context, rng)`, or import an owned transformed
   secret with `try_from_secret_key`. To encrypt publicly, create
   `client.public_key(rng)` and `context.public_key_encryptor(&public)`.
4. Allocate ciphertexts with `context.new_ciphertext(level)` and an N-coefficient
   plaintext output once. Reuse them with `client.encrypt_to`,
   `encrypt_centered_to` and `decrypt_to(ciphertext, level, output)`.
5. Bind `BfvEvaluator::new(&context, level)` for ciphertext addition,
   subtraction, negation, plaintext addition and dense negacyclic plaintext
   multiplication. Prepare `BfvModulusSwitch::new(&context, source_level)`
   and call `switch_to` to drop one final prime into the next prepared level.

Both coefficient embeddings accept exactly N canonical values in `[0,t)`.
Unsigned lifts m to m; centered uses `[-floor(t/2), ceil(t/2))`. Decryption
returns canonical values in `[0,t)`. These are coefficients, not slots.
`BfvCiphertext::as_view` and `as_mut_view` borrow storage without copying.

## Scaling and evaluation

Encryption satisfies `c0+c1*s = delta*lift(m)+e (mod Q)`, with
`delta=floor(Q/t)`. Private encryption computes `c0=delta*lift(m)+e-c1*s`
directly. Encoding is fused into coefficient noise before c0's single NTT.
Native public encryption computes `c0=pk0*u+e0+delta*lift(m)` and
`c1=pk1*u+e1`, reusing one ephemeral polynomial and one NTT per noisy component.
Ordinary operations retain native BFV storage.

Linear operations act on both components. `add_plain_to`/`add_plain_assign`
add the current level's delta-scaled lift to c0 and retain c1.
`mul_plain_to`/`mul_plain_assign` multiply both components by the **unscaled**
plaintext lift in `Z_t[X]/(X^N+1)`. Plaintext operations take an explicit
`PlaintextEmbedding`; centered lifting can reduce noise amplification.
Reducing message arithmetic modulo t can add encoding drift when `delta*t != Q`.

A switch from Q to `Q'=Q/p` computes exact coefficientwise nearest rounding
`round(c_i/p) mod Q'` for each component. Since p is odd, integer inputs have no
half-integer tie. The implementation uses the dropped residue's exact centered
lift, not approximate Hybrid-RNS ModDown. It needs only that limb's INTT and
transforms of its correction in retained limbs. Switching adds component-rounding
and scale-mismatch error; every destination level needs its own complete
recovery bound. Algebra, signs and noise contributions are explained in
[RNS phase conventions](../../guides/development/rns-phase-conventions.md).

## Recovery and levels

Each level owns a codec with `delta=floor(Q_level/t)` and the same t/gamma.
Recovery uses fast conversion to `{t,gamma}` and auxiliary correction. It returns
the **exact message under the codec's recovery bound**; it is not an exact-rounding
oracle for arbitrary phases. For a coefficient phase `delta*m+e`, a sufficient
condition is `abs(t*e-(Q_level % t)*m)/Q_level + k/gamma < 1/2`, where k is the
level's prime count. `codec(level).validate_noise_bound` checks a conservative
all-message bound for a supplied complete error magnitude and embedding.

Parameter construction checks sampling/basis pairing and sufficient fresh
private recovery using the error sampler's complete support. Lower-level
construction checks noiseless codec recovery. Neither proves a security level
or public/evaluated recovery. Public-key noise, all evaluation/drift terms and
every switch's rounding error must be included at the destination level.
A successful fresh encryption alone does not establish recovery after a chain.

Ciphertexts carry storage, not an authenticated level, key or transform identity.
Operations check complete lengths, and constructors check numerical modulus
order and geometry. Callers must supply the actual level, canonical NTT residues,
the same actual coefficient secret and this context's roots/evaluation order.
Equal lengths and moduli do not establish these identities. The optimized u64
NTT backend requires compatible Q primes below `2^62`.

## Advanced explicit workflows

The [encryption example](examples/coefficients.rs) shows the lower-level
`BfvSecretKeyContext`, explicit `U64DcrtTable` and `BfvDecryptWorkspace`
bindings. `size()` owns geometry, `base_q()` owns basis arithmetic, `codec()`
owns scaling/recovery constants and `encryption_parameters()` owns samplers.
These bindings remain available when another workflow already owns those resources.

`encrypt_plaintext_lift_crt_to` accepts **unscaled** canonical CRT lifts in
coefficient-domain, modulus-major Q order and applies delta once.
`encrypt_encoded_crt_to` accepts an **already-scaled** canonical phase, including
codec output, and never applies delta. Passing encoded output to the lift entry
would scale twice. `phase_to` writes DCRT output without INTT or decoding;
lower-level `decrypt_to` performs those operations with explicit scratch.

Raw GLWE retains `[a,b]` and `b-a*s`. `write_raw_glwe_to` explicitly writes
`[a=-c1,b=c0]`; `set_from_raw_glwe` imports `[c0=b,c1=-a]`. These boundaries copy
and negate canonical residues without allocation or NTT. The
[Hybrid-RNS example](examples/hybrid_rns_key_switch.rs) and raw comparison
benchmarks use them because existing switching/GGSW keys retain raw semantics.
`gadget_parameters` prepares codec-free decomposition weights for those raw
consumers; it is not a native BFV evaluation key.

## Resources and validation

The context owns one full-basis NTT table, one top-level parameter owner and one
codec for each requested lower level. Clients/evaluators borrow these resources.
The client owns one highest-level transformed secret and one recovery workspace;
lower recovery borrows their prefixes without cloning secrets or creating
samplers. The workspace has a phase buffer plus exactly the top codec's
`decode_scratch_len(N)` conversion elements; lower codecs reuse its prefix.
A single-prime codec needs no conversion elements.

An evaluator owns one reusable plaintext polynomial; a switch owns one
N-coefficient dropped-limb buffer and prepared constants. Prepared `*_to` and
`*_assign` operations allocate no temporary storage. `new_ciphertext` and
`decrypt` allocate their returned result. Public encryptors own one ephemeral
workspace. Concurrent operations use separate mutable workspace owners and can
share immutable context/key resources. Secret and ephemeral/recovery scratch are
erased on drop. Explicit `workspace_mut().zeroize()` or
`Zeroize::zeroize(&mut decrypt_workspace)` preserves allocation and geometry;
calls overwrite scratch without adding an erasure scan after every operation.

Complete length errors are rejected before output/scratch writes or sampling.
`BfvClient` additionally checks all plaintext values before RNG consumption.
The lower-level `BfvSecretKeyContext` and `BfvPublicKeyEncryptor` coefficient
entries check values through the codec after noise sampling and before c0's NTT.
Evaluator plaintext entries check all values before output/scratch writes.
Representation/range contracts for ciphertexts and CRT input remain unchecked
mathematical requirements. RNG/NTT/codec panics may leave partial output or
scratch. Per-method rustdoc owns the precise contracts.

## Features and checks

Default features are empty. `simd` forwards to shared arithmetic/codec backends
and follows their nightly SIMD requirements.

```sh
cargo check -p primus_bfv --all-targets
cargo test -p primus_bfv --lib --tests
cargo run -p primus_bfv --example leveled_coefficients
cargo run -p primus_bfv --example coefficients
cargo run -p primus_bfv --example hybrid_rns_key_switch
cargo clippy -p primus_bfv --all-targets -- -D warnings
cargo bench -p primus_bfv --bench leveled
cargo bench -p primus_bfv --bench public_encryption
cargo bench -p primus_bfv --bench key_switching
```

Small functional tests use independent direct-DFT/schoolbook and integer-rounding
oracles for phases, dense products, embeddings, boundary values and multiple
levels. They also protect raw bridges, wrong-scaling cases, complete checks,
workspace reuse/erasure and allocation contracts. Criterion measures individual
operations and a complete encrypt/evaluate/two-switch/decrypt request with
prepared resources. Raw comparison timings exclude bridges performed during setup.
