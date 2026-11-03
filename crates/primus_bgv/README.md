# primus_bgv

English | [简体中文](README.zh_CN.md)

Fixed-u64, rank-one leveled BGV over the q_i≡1 mod p family. Native ciphertexts
store `[c0,c1]` with phase `c0+c1*s=lift(m)+p*e`. The crate supports private/public
encryption, linear/plaintext operations, multiplication/square, p-preserving
relinearization/key switching/automorphisms, exact prime drop and optional slots.
Coefficient p can be composite; batching requires its own plaintext prime.

## Workflow

Start with [coefficients](examples/coefficients.rs): public encryption of
`3+2X` and `5+X`, one multiplication, and recovery of `15+13X+2X²`. Enable
`batching` for [slots](examples/slots.rs): encrypted element-wise multiplication
and a row rotation with n=N. The advanced [leveled coefficients](examples/leveled_coefficients.rs)
and [leveled slots](examples/leveled_slots.rs) combine square, automorphism,
secret change and two prime drops; the latter also demonstrates an n<N subring.

1. Prepare `BgvParameters::try_coefficients` or explicitly select Gaussian/CBD
   with `try_with_error_distribution`. `BgvContext::try_new` prepares one level;
   `try_with_levels(parameters, count)` prepares an explicit prime-drop chain.
2. `BgvClient::generate(&context,rng)` owns one full-N secret and erasing recovery
   scratch. Retain `client.public_key(rng)` and bind `context.public_key_encryptor`.
   Both client and public encryptor provide `encrypt`/`encrypt_centered`, which
   allocate only the returned ciphertext, and `_to` variants for prepared output.
3. Generate a `relinearization_key(level, config, rng)` and bind
   `BgvMultiplication::try_new(&context, &key)`. The key determines its level;
   `multiply_to`, `square_to` and `square_assign` perform tensor multiplication
   and relinearization using retained scratch, without online allocation.
4. For linear/plaintext operations prepare `BgvEvaluator::new(&context,level)`.
   Add/sub/neg operate on both components; `add_plain` changes c0, while
   `mul_plain` multiplies both components. Choose unsigned/centered
   `PlaintextEmbedding` explicitly. Advanced staged evaluation remains available:
   `mul_to`/`square_to` write an explicit `BgvQuadraticCiphertext`, then a
   `BgvRelinearizer` returns it to degree one.
5. Generate only the required `automorphism_key` and `key_switching_key` roles.
   Prepare `BgvAutomorphism` or `BgvKeySwitcher` once. The target client generates
   a switch key from the source client; an automorphism key returns σ(s) to s.
6. `BgvModulusSwitch::new(&context,level).switch_to` performs one adjacent prime
   drop. Recover with `client.decrypt_to(input,level,&mut output)`; `decrypt`
   allocates only the returned polynomial. These operations do not choose a
   noise policy or a drop schedule automatically.

Level zero contains all ordered primes; level l omits the last l primes. Context
owns one full-Q NTT table and distinct prefix CRT bases/recovery constants. The
single full-Q secret is borrowed by prefix. Level selection never changes N.
Storage wrappers check complete lengths but do not certify actual key, ordered
basis, canonical ciphertext residues or NTT identity; callers maintain them.

## Evaluation keys and exact prime drop

Use the existing `DecompositionConfig` to select radix and retained digits. Each
role key owns its actual decomposition and belongs to one modulus level; generate
keys separately for the levels used. Truncating a higher-level key's limbs cannot
produce a lower-level key, because Q, weights and dropped bits have changed.
`None` selects all available gadget digits, which can still discard low bits
when log_basis does not divide Q's bit width.

The switched component a is multiplied by p^-1 modulo Q **before decomposition**.
Columns have phase `p*g_j*h+p*e_j`, with h=s², the source secret, or σ(s).
Both digit noise and approximation residual therefore enter as p-multiple error.
Ordinary truncated BFV/GLWE switching does not establish this property. Three
role types prevent accidental relin/switch/automorphism-key substitution;
constructors reject different levels, N, p and ordered Q. Decomposition and key
columns remain owned by the role-specific implementation.
Same-parameter actual-secret identity remains a caller contract.

Dropping the final prime q uses the exact componentwise quotient
`(x-p*center_q(x*p^-1 mod q))/q mod (Q/q)`. It needs only the dropped limb's INTT,
one reusable N-element scratch, retained-limb correction NTTs and inverse factors.
It is not BFV nearest rounding. Since q≡1 mod p, the supported chain needs no
additional plaintext correction factor. General-prime chains are rejected.
See [BGV evaluation contracts](../../guides/development/bgv-evaluation.md) for
phase/residual/noise derivations and the shared componentwise GLev adapter.

## Exact recovery and noise

One signed coefficient error is sampled once across all RNS limbs and multiplied
by p. Gaussian/CBD use the actual configured laws; public ephemeral r is exact
CBD1, independently of the recipient secret law. Public-key phase is p*e_pk;
fresh public phase is `lift(m)+p*(e_pk*r+e0+e1*s)` in the full negacyclic ring.

Recovery inverse-transforms the full phase at the selected level, composes x∈[0,Q)
exactly, and returns x mod p below the centered threshold or (x-Q) mod p above it.
Q can exceed 128 bits. There is no BFV decoder, floating approximation or external
BigInt normal dependency. The intended integer phase at **each level** must stay
in (-Q/2,Q/2); crossing Q can change the plaintext modulo p.

Parameter construction checks the fresh-private sufficient bound
`p*maximum_error+(p-1) <= floor(Q/2)`. Lower-level preparation, evaluation-key
generation and functional examples do not certify public/evaluated noise or
security. Include full-ring convolutions, message carries, every decomposition
residual and every prime-drop correction. Correlated evaluation keys also have
their own security assumptions. Ciphertext moduli must be primes compatible with
the current u64 NTT backend (q_i<2^62); rootability checks do not prove primality.

## Slots and subrings

Optional `batching` consumes the shared `primus_encoding::BatchingEncoder`, also
used by BFV. A prime p≡1 mod 2n supplies n plaintext slots in two ±5^j rows.
`encode_to` zero-pads a slot prefix; `embed_to` maps f(Y) to f(X^(N/n)). Only the
plaintext uses n: actual secret, error, transforms and ciphertext retain N.
The basic n=N example encodes directly into the full plaintext polynomial and
decodes it after recovery. For n<N, `extract_to` checks subring membership after
full-N recovery, then `decode_to` recovers slots using caller scratch. p need not
support a full-N plaintext NTT in the subring workflow.

Use `rotation_exponent(k)` or `row_swap_exponent()` to choose an odd full-ring
automorphism key. `BgvAutomorphism::apply_to` executes the encrypted operation
and switches back to the original secret. The leveled slot example uses n32,
N128,p193, rotates/swaps rows and changes to a second full-N secret. All spare
slots remain zero at their permuted positions.

## Resources and commands

Context owns sampling/bases/table; clients, evaluators and prepared key operations
borrow it. Prepared encryption, tensor/square, linear/plaintext operations,
relin/switch/auto, adjacent prime drop and recovery allocate no memory. Secret,
secret-square/automorphism generation temporaries, public ephemeral and recovery
storage are erased on drop. `Zeroize::zeroize` explicitly erases a public
encryptor’s ephemeral while retaining its prepared allocation. Caller-owned
plaintext/output/batching buffers remain
under their owner's control. No Domain or generic coefficient type is added.

Default features are empty. `batching` enables shared slot encoding; `simd`
forwards to the existing nightly SIMD backends.

```sh
cargo run -p primus_bgv --example coefficients
cargo run -p primus_bgv --example slots --features batching
cargo run -p primus_bgv --example leveled_coefficients
cargo run -p primus_bgv --example leveled_slots --features batching
cargo test -p primus_bgv --features batching --lib --tests
cargo clippy -p primus_bgv --all-targets --features batching -- -D warnings
cargo bench -p primus_bgv --bench leveled --features batching
```

Tests use direct DFT, schoolbook convolution and independent arbitrary-width
integer oracles for key phases, signed gadget digits/residuals, exact quotients
and even-p boundaries. The `leveled` benchmark measures one complete fresh packed
request through multiplication/square/relin, rotation, a secret change, two prime
drops and slot recovery. Setup/key generation/allocation and final assertions
stay outside timing. The smaller `workflow` benchmark retains the basic
public-encrypt/plaintext-evaluate/recover workload. Parameters are functional
fixtures, not security presets.
