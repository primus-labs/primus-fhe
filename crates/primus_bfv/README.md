# primus_bfv

English | [简体中文](README.zh_CN.md)

BFV coefficient encryption and recovery over rank-one `u64` RNS GLWE. Each
ciphertext prime occupies one `u64`; their product Q can be wider than 64 bits.
The default backend is `BarrettModulus<u64>` with `U64DcrtTable`.

This crate currently owns BFV parameters, private/public message encryption,
plaintext recovery and gadget-parameter construction. A complete leveled BFV
evaluator, ciphertext multiplication/relinearization, slots and modulus-chain
operations are not provided yet. The unique coefficient codec remains in
`primus_encoding`; storage, keys and raw evaluation primitives come from
`primus_glwe_rns` and `primus_lattice`.

## Coefficient workflow

Run the complete [example](examples/coefficients.rs):

```sh
cargo run -p primus_bfv --example coefficients
```

1. Construct `BfvParameters::try_new(N, t, gamma, &Q, secret_law, sigma)`, or use
   `try_with_error_distribution` for an explicit Gaussian/CBD law.
2. Prepare one `U64DcrtTable` from the parameter polynomial length and ordered Q
   contexts. Generate the coefficient secret with `secret_key_sampler()`, then
   convert it with `DcrtGlweSecretKey::from_coeff_secret_key`.
3. Bind `BfvSecretKeyContext::try_new(&key, &parameters, &table)`. Generate a raw
   public key from `encryption_parameters()` and `base_q()`, then prepare a
   `BfvPublicKeyEncryptor` when public encryption is needed.
4. Allocate ciphertext/output storage and `BfvDecryptWorkspace::new(&parameters)`
   once. Reuse them with `encrypt_to`, `encrypt_centered_to` and `decrypt_to`.

Both coefficient encryption entries accept exactly N canonical values in
`[0,t)`. Unsigned embedding lifts m to m; centered embedding uses
`[-floor(t/2), ceil(t/2))`. Decryption always returns canonical values in `[0,t)`.
These are polynomial coefficient encodings, not SIMD slots.

## Scaling and representations

Encryption has phase `b-a*s = delta*lift(m)+e (mod Q)`, where
`delta=floor(Q/t)`. BFV encoding is fused into coefficient noise before the
body's single forward NTT. Public encryption also reuses one ephemeral
polynomial; each noisy ciphertext component is transformed once.

`encrypt_plaintext_crt_to` accepts **unscaled** canonical CRT plaintext lifts,
in coefficient-domain modulus-major Q order, and applies delta once. Feeding it
the already-scaled output of `BfvRnsCodec::encode_coeffs_to` would scale twice.
For a caller-provided encoded phase, use the codec-free raw encryption interface
in `primus_glwe_rns` instead.

`phase_to` writes one **DCRT** polynomial without inverse transformation or
decoding. `decrypt_to` computes that phase, performs INTT and invokes the unique
BFV coefficient codec. `gadget_parameters(log_basis, levels)` derives ordinary
codec-free gadget parameters sharing immutable samplers/base tables; gadget
weights are not BFV message scaling.

## Resources and validation

Prepared `*_to` calls allocate no temporary storage. The allocating public
`encrypt_plaintext_crt` and secret `decrypt` conveniences allocate only their
returned result. Public encryptors own their ephemeral workspace and require
mutable access; concurrent calls need separate encryptors. Keys, parameters and
tables remain shared. Decryption uses one phase buffer plus exactly
`codec.decode_scratch_len(N)` conversion elements, including zero conversion
elements for a single Q modulus.

Public ephemeral and decryption scratch are erased on drop. Explicit
`workspace_mut().zeroize()` or `Zeroize::zeroize(&mut decrypt_workspace)` erases
contents while preserving allocation/geometry for reuse. Calls overwrite
scratch; they do not add a full erasure pass after every operation.

Parameter construction checks ordered basis/sampler pairing and a sufficient
fresh private-key recovery bound using the error sampler's complete maximum
magnitude. Its unsigned bound also covers centered lifting. It does not prove
public-key/evaluated phase-noise recovery, NTT identity or a security level.
Bindings check geometry and numerical modulus order; actual secret and NTT
root/evaluation identity remain caller contracts. The optimized `u64` NTT backend
requires ciphertext primes below `2^62` and compatible with N.

Complete layout errors are rejected before writes/random sampling. Canonical
coefficient values are checked by the codec after noise sampling, before body
NTT; a codec, RNG, callback or transform panic can leave partial output/scratch.
See each method's rustdoc for exact unchecked mathematical conditions.

## Features and checks

Default features are empty. `simd` forwards to the shared GLWE/codec backends
and uses their nightly SIMD requirements; it does not select another scheme.

```sh
cargo check -p primus_bfv --all-targets
cargo test -p primus_bfv --lib --tests
cargo run -p primus_bfv --example coefficients
cargo clippy -p primus_bfv --all-targets -- -D warnings
cargo bench -p primus_bfv --bench public_encryption
cargo bench -p primus_bfv --bench key_switching
```

Tests cover coefficient embeddings, delta applied once against independently
computed CRT encoding, direct-DFT/u128 recovery oracles, plaintext products,
ordered-domain/complete-layout rejection, error sources, sampler sharing,
workspace erasure/reuse and separate allocation contracts. Tests use small
functional parameters; benchmark timings belong to explicit benchmark runs.
