# primus_bgv

English | [简体中文](README.zh_CN.md)

Fixed-u64, rank-one leveled BGV with ciphertext primes coprime to plaintext p. Native ciphertexts store `[c0,c1]`, with phase `c0+c1*s`. Their intended integer representative is `z=lift(f*m mod p)+p*e`; recovery requires z in `(-Q/2,Q/2)`, where the centered native phase equals z. The canonical invertible correction factor f follows the ciphertext's operation history. The crate provides private/public encryption, linear/plaintext evaluation, multiplication, relinearization, key switching, automorphisms, prime drops and optional slots.

## Start with coefficients or slots

[coefficients](examples/coefficients.rs) evaluates `(message+1)*scalar` twice.
[slots](examples/slots.rs) applies the same operations slotwise with `n=N`.
They reuse context, public key, evaluator and output; ciphertext multiplication
and evaluation-key configuration are introduced separately.

```sh
cargo run -p primus_bgv --example coefficients
cargo run -p primus_bgv --example slots --features batching
```

1. Build `BgvParameters::try_coefficients(N,p,&Q,secret_law,error_law)` with a
   Gaussian or centered-binomial `ErrorDistribution`. Move it into
   `BgvContext::try_new(parameters)`.
2. Generate `BgvClient::generate(&context,rng)`, retain `client.public_key(rng)`
   and bind `context.public_key_encryptor(&key)`.
3. Prepare `evaluation::BgvEvaluator::new(&context,0)`, `context.new_plaintext()`
   and `context.new_ciphertext(0)`. Use `encrypt_centered_to`,
   `add_plain_assign` and `mul_plain_assign` with centered lifts, then recover
   at the recorded level with `client.decrypt_to(&result, &mut plaintext)`.
4. With `batching`, prepare `context.batching_encoder()` once. Use `encode_to`
   directly on context-sized plaintexts and `decode` on the recovered polynomial.
5. Reuse prepared resources with new messages and fresh encryption coins.
   The coefficient example reuses caller-owned buffers. Allocating conveniences
   are available when the caller needs an owned return value.

Both encryption embeddings accept N canonical coefficients in `[0,p)`;
`Unsigned` lifts them directly and `Centered` uses `[-floor(p/2),ceil(p/2))`.
Recovery returns canonical coefficients. Example parameters demonstrate
functionality and are not security presets.

## Advanced workflows

Find key material and Radix/Hybrid configuration in `keys`, prepared
operations in `evaluation`, ordinary circuit budgets in `planning` and
shared key contributions in `collective`. Use `advanced::tensor_to` or
`advanced::square_to` for explicit degree-two output without plaintext scratch.

| Example | Additional concepts |
| --- | --- |
| [ciphertext_multiplication](examples/ciphertext_multiplication.rs) | One relin key and `BgvMultiplication`; two encrypted coefficient products reuse the operation |
| [leveled_coefficients](examples/leveled_coefficients.rs) | Generated ordinary primes, a public circuit budget, square, `X→X^5`, Alice→Bob switching and two drops; `--hybrid` selects actual QP keys |
| [leveled_slots](examples/leveled_slots.rs) | Explicit `n<N` packing, row rotation/swap, key switching and two prime drops with reusable outputs |
| [collective](examples/collective.rs) | Individual raw shares, public-key contributions, two-round relin and online client handoff |

```sh
cargo run -p primus_bgv --example ciphertext_multiplication
cargo run -p primus_bgv --example ciphertext_multiplication -- --hybrid
cargo run -p primus_bgv --example leveled_coefficients
cargo run -p primus_bgv --example leveled_coefficients -- --hybrid
cargo run -p primus_bgv --example leveled_slots --features batching
cargo run -p primus_bgv --example collective
```

The multiplication example selects signed-radix Q keys by default. `--hybrid`
selects partitioned QP keys; basic examples take no arguments. In code, share
`context.radix_key_parameters(level,config)` or
`context.hybrid_key_parameters(level,decomposition_count,&key_p)` through cloned
`Arc`s across role keys. Key P needs its own security/error budget. Shared
numerical metadata alone does not prove an imported secret or transform's provenance;
see the [native Hybrid contract](../../guides/development/native-hybrid-keys.md).

## Generate parameters and admit a declared circuit

`BgvParameterRequest::create_context` generates and validates actual NTT primes
from explicit N, p, prime width/count, levels and sampler laws. Q primes support the full-ring NTT and need not be one modulo p. `BgvCircuitPlan::try_new(&context,&operations,backend)` separately admits a static ordinary circuit. It reports every node's correction factor, full integer phase, error envelope, component contributions, centered capacity and remaining margin;
a rejection names its node/level and required modulus bit width. This is a
bounded arithmetic workflow: callers adjust the explicit resources when needed.

Use `plan.key_config(level)` for the actual ordinary relin, automorphism and
switching keys. `BgvBudgetBackend::hybrid` generates a distinct key P, and its
actual per-level QP exposures are included in `plan.security_inputs()`. These
are exact inputs for a separate security review and remain `NotEvaluated`.
Successful generation, admission or decryption does not claim 128-bit security.
The budget uses hard sampler supports and full-ring bounds, so correlated
inputs/keys remain covered; it may conservatively reject feasible circuits.
It covers the declared ordinary operations, excluding collective keys, raw SSLE
arithmetic and privacy openings. See the [budget derivation](../../guides/development/bgv-evaluation.md#public-static-circuit-budgets)
and [parameter/security-reference guide](../../guides/development/ordinary-parameter-budgets.md).

## Levels, slots and numerical contracts

Level zero uses all ordered Q primes; level l removes the last l primes without
changing N. `try_with_levels(parameters,count)` prepares only the requested
prefixes. Generate role keys at each actual level; slicing a higher-level key
matrix is not a lower-level key constructor. Prepared multiplication,
relinearizer, switcher and automorphism derive their level from their role key.
Linear evaluation, key generation and prime drops select it explicitly. Ordinary decryption reads the ciphertext's bound level.

Fresh encryption has factor f=1. Multiplication multiplies the input factors modulo p, while a prime drop changes f to `f*q^-1 mod p`. Relinearization, secret switching and automorphisms preserve the factor. Same-level inputs can therefore have different factors; addition/subtraction automatically aligns them with public centered scalars before combining, and plaintext addition uses the factor-weighted message lift. These scalars contribute to the evaluated phase bound. Read `ciphertext.correction_factor()` when an external consumer needs the value; do not infer it from the level.

Radix keys multiply the switched component by `p^-1 mod Q` before decomposition
and use phases `p*g_j*h+p*e_j`; approximation residual and key noise stay
p-multiples. The exact component prime drop is
`(x-p*center_q(x*p^-1 mod q))/q mod (Q/q)`. It differs from BFV nearest rounding and supports general coprime prime chains through the factor update above. Signed digits, truncated residuals, Hybrid correction and complete drop bounds are derived in
[BGV evaluation](../../guides/development/bgv-evaluation.md).

Recovery composes the selected-level phase exactly, including Q beyond 128 bits,
and reduces its centered lift modulo p, then removes f with its inverse modulo p. The intended integer phase at **every level** must remain in `(-Q/2,Q/2)`. Parameter construction checks only a
sufficient fresh-private bound, `p*maximum_error+(p-1) <= floor(Q/2)`; public and
evaluated recovery need their complete noise bounds. Errors are sampled once
as signed coefficients across all RNS limbs. Public ephemeral r is exact CBD1;
fresh public phase is `lift(m)+p*(e_pk*r+e0+e1*s)` in the full negacyclic ring.
Ciphertext primes must support the actual NTT and satisfy `q_i<2^62`;
rootability checks do not certify primality or security.

Coefficient p may be composite, but every ciphertext prime and correction factor must be coprime to p. Slots require prime `p≡1 mod 2n`; the context
factory chooses `n=N`, while `leveled_slots` demonstrates an explicit smaller
encoder. `embed_to` maps `f(Y)` to `f(X^(N/n))`, with full-N secrets/errors and
ciphertexts. After recovery, `extract_to` verifies the subring before decoding.
`encode_to` zero-pads a slot prefix; `encode`/`decode` allocate results, while
`decode_to` uses caller scratch. Row rotation uses signed left steps modulo
`n/2`; row swap exchanges rows without reversal. Encoder mismatches reject
before key randomness. Their precise contracts are in the
[encoding crate](../primus_encoding/README.md) and key-generation rustdoc.

Flexilect retains its separate `q_i≡1 mod p` drop policy, factor-one ciphertexts and `Q=p*Delta+1` bridge/noise contracts. Its admission layer keeps those restrictions when using the more general ordinary BGV core.

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
`partial_phase_to` produces the physical contribution `c1*s_i`, without removing f. An enclosing protocol authenticates the factor with the complete ciphertext, supplies c0, privacy flooding, complete noise/security bounds and opening authorization. After combining all physical shares, it takes the centered phase modulo p and removes f once. These primitives alone are not an authenticated opening protocol.

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
before writes/RNG consumption. Context-created ciphertexts retain their local
context, level and correction factor. Prepared keys must belong to that same
context; bound foreign-context or wrong-level values reject before writes.
`client.decrypt(&ciphertext)` uses its bound level. This does not prove the actual
same-secret relationship or authenticate residues edited through `AsMut`. Explicit
`from_raw` / `zero_raw` containers and `decrypt_at_level` / `decrypt_at_level_to`
preserve advanced caller contracts. Fresh raw storage starts with factor one.
`context.try_bind_ciphertext(raw,level)` checks storage, canonical residues and
the factor. Declare the factor of received words with
`context.try_import_ciphertext(words,level,factor)`. Both require
`0<factor<p` and `gcd(factor,p)=1`. The caller still authenticates the scalar
and attests the actual transform and secret.

```rust,ignore
let imported = context.try_import_ciphertext(received_words, level, received_factor)?;
let message = client.decrypt(&imported);
// Prepared outputs are passed directly; their factor is updated with their data.
evaluator.add_to(&left, &right, &mut output);
```

Borrow the whole ciphertext for input and output. Operations see the stored
factor and level with the residue buffer, and an output operation updates the
owner's factor. See [context, level and raw interoperability](../../guides/development/scheme-context-binding.md).

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

## Public storage

`BgvContext::to_public_bytes()` and `from_public_bytes(bytes, limits)` store complete public parameters and restore a new local context. Its `export_*` / `import_*` methods cover native ciphertexts, public keys and typed relinearization, switching and automorphism keys, including Radix and Hybrid Q/P metadata. Set `PublicObjectLimits` for your deployment; imports check version, role, full geometry, canonical residues and actual NTT representation before accepting owned data. BGV correction factors survive storage and are checked as canonical units.

No secret or local binding pointer is serialized. Authenticate the public object together with its application source/target identities and declared budgets. Structural validation does not prove honest key generation or the claimed secret relationship. Independent key imports can repeat numerical metadata/P-table preparation; no implicit key cache is introduced.

See [public storage](../../guides/development/public-storage.md) and the [BGV public-worker example](../primus_bgv/examples/public_worker.rs), which keeps the client secret local and evaluates through public byte containers. These containers do not add headers to a protocol's online round payloads.
