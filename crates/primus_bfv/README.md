# primus_bfv

English | [简体中文](README.zh_CN.md)

BFV coefficient encryption and recovery with native physical components
`[c0,c1]` and phase `c0+c1*s`. The rank-one backend uses `u64` residues,
`BarrettModulus<u64>` and `U64DcrtTable`; the product Q may exceed 64 bits.
The actual coefficient secret is unchanged when sharing numerical secret storage
with `primus_glwe_rns`.

The crate owns BFV parameters, ciphertext/public-key semantics, private/public
message encryption and plaintext recovery. A complete leveled evaluator,
ciphertext multiplication/relinearization, slots and modulus-chain operations
are not provided yet. The unique coefficient codec remains in `primus_encoding`;
RNS arithmetic, NTTs, samplers and secret storage are reused from lower layers.

## Coefficient workflow

Run the complete [example](examples/coefficients.rs):

```sh
cargo run -p primus_bfv --example coefficients
```

1. Construct `BfvParameters::try_new(N, t, gamma, &Q, secret_law, sigma)`, or use
   `try_with_error_distribution` for an explicit Gaussian/CBD law.
2. Prepare one `U64DcrtTable` from `poly_length()` and `base_q().moduli()`.
   Generate the coefficient secret with
   `encryption_parameters().secret_key_sampler()`, then convert it with
   `DcrtGlweSecretKey::from_coeff_secret_key`.
3. Bind `BfvSecretKeyContext::try_new(&key, &parameters, &table)`. When needed,
   generate `BfvPublicKey::new(&client, rng)` and prepare a
   `BfvPublicKeyEncryptor::try_new(&public, &parameters, &table)`.
4. Allocate `BfvCiphertext`, plaintext output and
   `BfvDecryptWorkspace::new(&parameters)` once; reuse them with `encrypt_to`,
   `encrypt_centered_to` and `decrypt_to`.

Both coefficient entries accept exactly N canonical values in `[0,t)`.
Unsigned embedding lifts m to m; centered embedding uses
`[-floor(t/2), ceil(t/2))`. Decryption returns canonical values in `[0,t)`.
These are polynomial coefficients, not SIMD slots.

## Scaling and representations

Encryption satisfies `c0+c1*s = delta*lift(m)+e (mod Q)`, with
`delta=floor(Q/t)`. Private encryption computes `c0=delta*lift(m)+e-c1*s`
directly. Encoding is fused into coefficient noise before c0's single NTT.
Native public encryption computes `c0=pk0*u+e0+delta*lift(m)` and
`c1=pk1*u+e1`, reusing one ephemeral polynomial and one NTT per noisy component.
No ordinary operation converts an entire ciphertext to raw GLWE.

`encrypt_plaintext_lift_crt_to` accepts **unscaled** canonical CRT lifts in
coefficient-domain, modulus-major Q order and applies delta once.
`encrypt_encoded_crt_to` instead accepts an **already-scaled** canonical phase,
including codec output, and never applies delta. Feeding encoded output to the
lift entry would scale twice. The separate method names make the distinction
explicit without another intermediate polynomial.

`phase_to` writes a **DCRT** polynomial without INTT or decoding. `decrypt_to`
extracts that phase, performs INTT and invokes the unique BFV codec.
`size()` owns storage geometry, `base_q()` owns basis arithmetic, `codec()` owns
scaling/recovery constants and `encryption_parameters()` owns prepared samplers;
BFV does not mirror every underlying accessor.

Raw GLWE retains `[a,b]` and `b-a*s`. `write_raw_glwe_to` explicitly writes
`[a=-c1,b=c0]`; `set_from_raw_glwe` imports `[c0=b,c1=-a]`. These boundaries copy
and negate canonical residues without allocation or NTT. The
[Hybrid-RNS example](examples/hybrid_rns_key_switch.rs) and raw comparison
benchmarks use these bridges because their existing switching/GGSW keys retain
raw semantics. `gadget_parameters` prepares decomposition weights for those raw
consumers; it carries no encryption sampler and is not a native BFV evaluator.

Component, tensor, evaluation-key and opening signs are derived in
[RNS phase conventions](../../guides/development/rns-phase-conventions.md).

## Resources and validation

Prepared `*_to` calls allocate no temporary storage. The public
`encrypt_plaintext_lift_crt` and secret `decrypt` conveniences allocate only their
returned result. Public encryptors own one ephemeral workspace and require
mutable access; concurrent calls use separate encryptors with shared keys,
parameters and tables. Decryption retains one phase buffer plus exactly
`codec().decode_scratch_len(N)` conversion elements, including zero conversion
elements for a single Q prime.

Ephemeral/decryption scratch is erased on drop. Explicit
`workspace_mut().zeroize()` or `Zeroize::zeroize(&mut decrypt_workspace)` erases
contents while preserving allocation and geometry. Calls overwrite scratch;
they do not add an erasure pass after every operation.

Parameter construction validates sampling/basis pairing and a sufficient fresh
private recovery bound from the error sampler's complete support. It does not
establish public/evaluated recovery or a security level. Actual secret and NTT
root/evaluation identity remain caller contracts. Operational bindings check
geometry and numerical modulus order once; there is no additional public Domain
type. The optimized u64 NTT backend requires Q primes below `2^62` compatible
with N.

Complete length errors are rejected before sampling/writes. The codec checks
coefficient values after noise sampling, before c0's NTT; codec/RNG/NTT panics
can leave partial output or scratch. Per-method rustdoc owns exact contracts.

## Features and checks

Default features are empty. `simd` forwards to shared arithmetic/codec backends
and follows their nightly SIMD requirements.

```sh
cargo check -p primus_bfv --all-targets
cargo test -p primus_bfv --lib --tests
cargo run -p primus_bfv --example coefficients
cargo run -p primus_bfv --example hybrid_rns_key_switch
cargo clippy -p primus_bfv --all-targets -- -D warnings
cargo bench -p primus_bfv --bench public_encryption
cargo bench -p primus_bfv --bench key_switching
```

Tests use small functional parameters. Direct-DFT/u128 oracles check native
component signs against the actual coefficient secret, common RNS residuals,
public-key phases, embeddings and exact recovery. Tests also protect explicit
raw bridges, wrong-scaling negative cases, full-length/basis checks, error
sources, workspace reuse/erasure and separate allocation contracts. Criterion
measures explicit workflows; raw comparison timings exclude setup bridges.
