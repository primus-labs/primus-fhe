# primus_bgv

English | [简体中文](README.zh_CN.md)

Fixed-u64, rank-one BGV coefficient and optional packed-slot workflows. Native
ciphertexts store `[c0,c1]` with phase `c0+c1*s = lift(m)+p*e`. The initial
ciphertext family requires every q_i to be 1 modulo p. Private/public encryption,
linear operations and unscaled plaintext addition/multiplication are supported;
ciphertext multiplication, relinearization, encrypted rotations and modulus
switching are subsequent work.

## Workflow

1. Construct `BgvParameters::try_coefficients(N,p,&moduli,secret_law,sigma)`, or
   select the existing Gaussian/CBD error law with `try_with_error_distribution`.
2. Consume parameters into one `BgvContext`. `BgvClient::generate` samples one
   full-N secret and owns reusable erasing recovery scratch. Advanced callers
   can transfer an existing transformed secret with `try_from_secret_key`.
3. Prepare outputs with `context.new_ciphertext()`. Use the client's private
   encryptor, or generate `client.public_key(rng)` and bind
   `context.public_key_encryptor(&key)` for public encryption.
4. Prepare `BgvEvaluator::new(&context)` once. Evaluate add/sub/neg and
   add_plain/mul_plain with `_to` or `_assign`, selecting unsigned or centered
   `PlaintextEmbedding`. Both native components participate in multiplication;
   plaintext lifts have no BFV Delta or extra p factor.
5. Recover canonical coefficients with `client.decrypt_to(input,&mut output)`.
   The convenience `decrypt` allocates the returned polynomial.

See [coefficients](examples/coefficients.rs) for a complete public-encryption,
plaintext-evaluation and exact-recovery example. Plaintext and output lengths
are checked before RNG or writes. Ciphertext canonical residues, actual secret,
ordered basis and NTT identity remain mathematical caller contracts.

## Exact recovery and noise

One coefficient error is sampled once, encoded across all RNS limbs, then scaled
by p. Gaussian and CBD use the backend's actual distributions. Public ephemeral
r uses CBD1 independently of the recipient secret law. Public-key phase is
p*e_pk; a fresh public ciphertext has full error
`p*(e_pk*r+e0+e1*s)`, with products in the full negacyclic ring.

Decryption computes the phase, inverse NTT, and exact CRT composition x in [0,Q).
It returns x mod p below the centered threshold and `(x-Q) mod p` above it.
The latter correction is necessary even though Q mod p=1. Q may exceed 128 bits;
reconstruction uses existing multi-limb arithmetic, with no BFV decoder, floating
point approximation or BigInt normal dependency.

The intended integer phase must remain in (-Q/2,Q/2). Reducing an overflowing
phase by Q can change its message modulo p. Parameter construction checks the
fresh-private sufficient bound `p*maximum_error+(p-1) <= floor(Q/2)`, covering
both unsigned and centered lifts. Public/evaluated bounds must additionally
include public-key error, full-ring convolutions, plaintext carries and every
operation; private admission does not certify those circuits or security.
Ciphertext moduli must be primes compatible with the current u64 NTT backend
(q_i < 2^62); rootability checks are not primality certification.

## Slots and subrings

Enable `batching` to use the shared `primus_encoding::BatchingEncoder`, also
consumed by BFV. A prime p congruent to 1 modulo 2n supplies n slots in two
rows indexed by ±5^j. The encoder owns the small-n plaintext NTT; its slot
rotation mapping does not apply encrypted rotation or generate evaluation keys.

Encode a prefix of slots (unused slots become zero), then `embed_to` maps
f(Y) to f(X^(N/n)) with all off-stride coefficients zero. Only the plaintext
uses the smaller ring. The actual secret, error, NTT and ciphertext retain N.
After full-N decryption, `extract_to` validates the subring and `decode_to`
recovers slots with prepared scratch. p need only support the plaintext n,
while each ciphertext q_i must support the full N. The [slots example](examples/slots.rs)
uses n32, N128, p193, where a full-N plaintext NTT is unavailable.

## Resources and commands

Context owns one ordered basis, sampling state and full-N transform table.
Clients/evaluators/public encryptors borrow it. Prepared coefficient encryption,
exact recovery and evaluator operations allocate no memory; secret, ephemeral
and recovery storage is erased on drop. Ciphertext/view wrappers keep storage
semantics without adding a Domain or generic coefficient type.

Default features are empty. `batching` enables shared slot encoding; `simd`
forwards to the existing nightly SIMD backends.

```sh
cargo run -p primus_bgv --example coefficients
cargo run -p primus_bgv --example slots --features batching
cargo test -p primus_bgv --features batching --lib --tests
cargo clippy -p primus_bgv --all-targets --features batching -- -D warnings
cargo bench -p primus_bgv --bench workflow --features batching
```

Tests use independent DFT, schoolbook phase and multi-limb integer oracles,
including even-p centered halves and 150-bit Q. The benchmark measures a whole
packed request, including actual sampling, encode/embed, public encryption,
plaintext evaluation, exact recovery and slot extraction/decoding. Resource
preparation is outside timing. Parameters and fixed seeds are functional fixtures,
not security presets.
