# primus_bgv

English | [简体中文](README.zh_CN.md)

Fixed-u64, rank-one leveled BGV for the `q_i ≡ 1 (mod p)` family. Native
ciphertexts store `[c0,c1]` with phase `c0+c1*s=lift(m)+p*e`. The crate provides
private/public encryption, linear/plaintext evaluation, multiplication,
relinearization, key switching, automorphisms, prime drops and optional slots.

## Start with coefficients or slots

[coefficients](examples/coefficients.rs) evaluates `(message+1)*scalar` twice.
[slots](examples/slots.rs) applies the same operations slotwise with `n=N`.
They reuse context, public key, evaluator and output; ciphertext multiplication
and evaluation-key configuration are introduced separately.

```sh
cargo run -p primus_bgv --example coefficients
cargo run -p primus_bgv --example slots --features batching
```

1. Build `BgvParameters::try_coefficients(N,p,&Q,secret_law,sigma)` and move it
   into `BgvContext::try_new(parameters)`. Explicit Gaussian/CBD selection uses
   `try_with_error_distribution`.
2. Generate `BgvClient::generate(&context,rng)`, retain `client.public_key(rng)`
   and bind `context.public_key_encryptor(&key)`.
3. Prepare `BgvEvaluator::new(&context,0)`, `context.new_plaintext()` and
   `context.new_ciphertext(0)`. Public encryption is `encrypt_centered`; linear
   evaluation uses `add_plain_assign` and `mul_plain_to` with an explicit
   `PlaintextEmbedding`. Recover with `client.decrypt(&result,level)`.
4. With `batching`, prepare `context.batching_encoder()` once. Use `encode_to`
   directly on context-sized plaintexts and `decode` on the recovered polynomial.
5. Reuse prepared resources with new messages and fresh encryption coins.
   The basic examples use allocating encryption/decryption conveniences;
   corresponding `*_to` calls reuse caller-owned outputs.

Both encryption embeddings accept N canonical coefficients in `[0,p)`;
`Unsigned` lifts them directly and `Centered` uses `[-floor(p/2),ceil(p/2))`.
Recovery returns canonical coefficients. Example parameters demonstrate
functionality and are not security presets.

## Advanced workflows

| Example | Additional concepts |
| --- | --- |
| [ciphertext_multiplication](examples/ciphertext_multiplication.rs) | One relin key and `BgvMultiplication`; two encrypted coefficient products reuse the operation |
| [leveled_coefficients](examples/leveled_coefficients.rs) | Square, `X→X^5`, Alice→Bob key switching, plaintext addition and two prime drops |
| [leveled_slots](examples/leveled_slots.rs) | Explicit `n<N` packing, row rotation/swap, key switching and two prime drops with reusable outputs |
| [collective](examples/collective.rs) | Individual raw shares, public-key contributions, two-round relin and online client handoff |

```sh
cargo run -p primus_bgv --example ciphertext_multiplication
cargo run -p primus_bgv --example ciphertext_multiplication -- --hybrid
cargo run -p primus_bgv --example leveled_coefficients
cargo run -p primus_bgv --example leveled_slots --features batching
cargo run -p primus_bgv --example collective
```

The multiplication example selects signed-radix Q keys by default. `--hybrid`
selects partitioned QP keys; basic examples take no arguments. In code, share
`context.radix_key_parameters(level,config)` or
`context.hybrid_key_parameters(level,decomposition_count,&key_p)` through cloned
`Arc`s across role keys. Key P needs its own security/error budget. Shared
numerical metadata establishes neither actual secret nor transform provenance;
see the [native Hybrid contract](../../guides/development/native-hybrid-keys.md).

## Levels, slots and numerical contracts

Level zero uses all ordered Q primes; level l removes the last l primes without
changing N. `try_with_levels(parameters,count)` prepares only the requested
prefixes. Generate role keys at each actual level; slicing a higher-level key
matrix is not a lower-level key constructor. Prepared multiplication,
relinearizer, switcher and automorphism derive their level from their role key.
Linear evaluation, decryption, key generation and prime drops select it explicitly.

Radix keys multiply the switched component by `p^-1 mod Q` before decomposition
and use phases `p*g_j*h+p*e_j`; approximation residual and key noise stay
p-multiples. The exact component prime drop is
`(x-p*center_q(x*p^-1 mod q))/q mod (Q/q)`. It differs from BFV nearest rounding;
general-prime chains are unsupported. Signed digits, truncated residuals,
Hybrid correction and complete drop bounds are derived in
[BGV evaluation](../../guides/development/bgv-evaluation.md).

Recovery composes the selected-level phase exactly, including Q beyond 128 bits,
and reduces its centered lift modulo p. The intended integer phase at **every
level** must remain in `(-Q/2,Q/2)`. Parameter construction checks only a
sufficient fresh-private bound, `p*maximum_error+(p-1) <= floor(Q/2)`; public and
evaluated recovery need their complete noise bounds. Errors are sampled once
as signed coefficients across all RNS limbs. Public ephemeral r is exact CBD1;
fresh public phase is `lift(m)+p*(e_pk*r+e0+e1*s)` in the full negacyclic ring.
Ciphertext primes must support the actual NTT and satisfy `q_i<2^62`;
rootability checks do not certify primality or security.

Coefficient p may be composite. Slots require prime `p≡1 mod 2n`; the context
factory chooses `n=N`, while `leveled_slots` demonstrates an explicit smaller
encoder. `embed_to` maps `f(Y)` to `f(X^(N/n))`, with full-N secrets/errors and
ciphertexts. After recovery, `extract_to` verifies the subring before decoding.
`encode_to` zero-pads a slot prefix; `encode`/`decode` allocate results, while
`decode_to` uses caller scratch. Row rotation uses signed left steps modulo
`n/2`; row swap exchanges rows without reversal. Encoder mismatches reject
before key randomness. Their precise contracts are in the
[encoding crate](../primus_encoding/README.md) and key-generation rustdoc.

## Collective and one-use protocol responsibilities

Collective plans borrow each owner's `DcrtGlweSecretKey<u64>` and check numerical
geometry, ordered Q and declared law before sampling. This family requires exact
CBD1 (`SparseTernary`) shares and CBD21 errors. Keep the sole raw secret during
setup, then consume it into a client for actual input/recovery. Two-round state
is non-cloneable and erases its key-domain share and ephemeral on all exits.
Hybrid key masks/contributions use QP; public-key and additive inputs remain Q.

Authenticate context, role, source/target, roster and round before checked import.
Callers reject duplicate/missing owners, bind the frozen first round and enforce
single use. Metadata cannot prove the actual NTT convention, CBD1 sampling or
secret relation. `BgvSeededInput` samples an independent complete uniform A;
`try_from_common_mask` imports an authenticated array with caller-owned
provenance. A public short seed is not a full-ring statistical certificate, and
A must not reuse a public-key mask or derive from selection/lookup key bytes.
`partial_phase_to` produces only `c1*s_i`; an enclosing protocol supplies c0,
privacy flooding, complete noise/security bounds and opening authorization.
These primitives alone are not an authenticated opening protocol.

## Resources and verification

Context owns samplers/recovery bases and a shared immutable full-Q transform.
`shared_table()` / `try_with_table` support paired BFV/BGV contexts after N and
ordered-Q checks; scheme recovery constants stay distinct. Clients own one
transformed secret and erasing recovery workspace. Prepared operations borrow
context/keys and own mutable scratch; concurrent requests need independent
operation owners. Prepared `_to`/`_assign` evaluation and recovery allocate no
temporary storage. Secrets, generation temporaries, public ephemeral and recovery
scratch follow their erasure contracts; `Zeroize` can clear the public encryptor
without discarding its allocation. Consuming `into_secret_key` transfers the
sole allocation; cross-scheme use still requires matching actual roots/order.

`BgvEvaluator::new` owns its plaintext scratch and is the simplest default.
For sequential operations sharing a worker buffer, `with_plaintext_scratch`
borrows its exact active N·|Q| prefix; do not lend that buffer concurrently.

Public entries check their documented complete lengths and plaintext conditions
before writes/RNG consumption. Storage types do not authenticate level, secret,
canonical ciphertext residues or NTT identity. Per-method rustdoc owns exact
panic, correctness and partial-write contracts.

Default features are empty. `batching` enables shared slot encoding; `simd`
forwards the existing nightly backends. Runtime NTT intrinsic dispatch is
independent of that feature: disabling `simd` does not force scalar NTT.

`parallel` enables bounded DCRT prefix forward/inverse NTT scheduling in the
connected key-generation and gadget-product paths. Each prefix with N≥4096 and
at least two limbs uses at most four contiguous tasks; bound total pool threads
with `RAYON_NUM_THREADS` or `ThreadPool::install`. It is off by default, leaving
this NTT path serial without pool initialization. Random sampling stays serial.

```sh
cargo test -p primus_bgv --lib --tests --features batching
cargo clippy -p primus_bgv --all-targets --features batching -- -D warnings
cargo bench -p primus_bgv --bench leveled --features batching
```

The focused `workflow` bench measures public-encrypt/plaintext-evaluate/recover;
`leveled` measures a complete packed request. Setup and validation stay outside
timing. Independent DFT, schoolbook and wide-integer oracles protect phase,
residual, exact quotient and boundary contracts. See the
[testing guide](../../guides/development/testing.md) for feature and consumer checks.
