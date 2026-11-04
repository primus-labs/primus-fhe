# primus_bfv

English | [简体中文](README.zh_CN.md)

BFV coefficient and slot encryption/evaluation with native components `[c0,c1]`
and phase `c0+c1*s=delta*lift(m)+e`, where `delta=floor(Q/t)`. The rank-one
backend uses `u64` residues, `BarrettModulus<u64>` and `U64DcrtTable`; Q can
exceed 64 bits. Arithmetic, NTTs, samplers, secret storage and encoding are
shared with the lower crates. Optional `batching` adds shared slot encoding.

## Coefficient workflow

Start with [coefficients](examples/coefficients.rs): public encryption, one
ciphertext multiplication and coefficient recovery, with one setup reused for two requests.

```sh
cargo run -p primus_bfv --example coefficients
```

1. Construct `BfvParameters::try_coefficients(N,t,&Q,secret_law,sigma)` and move
   it into `BfvContext::try_new(parameters)`.
2. Generate `BfvClient::generate(&context,rng)`, create `client.public_key(rng)`
   and bind `context.public_key_encryptor(&public_key)`.
3. Prepare plaintexts with `context.new_plaintext()` and ciphertext outputs with
   `context.new_ciphertext(level)`; their lengths come from the context.
4. Generate `client.relinearization_key(level,config,rng)` and prepare
   `BfvMultiplication::try_new(&context,&relin_key)` once. Its `multiply_to`
   and `square_to` return ordinary degree-one ciphertexts; `square_assign`
   overwrites the input. Internal scale/relinearization scratch is reused.
5. Reuse setup and the prepared multiplication for each request. The basic
   example uses `encrypt_centered` and `decrypt`, which allocate their results;
   `multiply_to` reuses its output. Use `encrypt_centered_to` and `decrypt_to`
   when caller-owned buffers and zero online allocation are needed.

The multiplication takes its level from the key and prepares computation-only
auxiliary primes automatically. They never enlarge the encryption/key modulus.
The parameters in the examples demonstrate functionality and are not security
presets. Full circuit recovery requires a bound on all accumulated error terms.

Both encryption embeddings accept exactly N canonical values in `[0,t)`.
Unsigned lifts m to m; centered uses `[-floor(t/2),ceil(t/2))`. Recovery returns
canonical coefficients in `[0,t)`. `client.encrypt` and `encrypt_centered` also
provide private encryption. Allocating encryption/decryption is convenient for
one-off calls; prepared `*_to` calls reuse caller-owned outputs.

## Slots

Enable `batching` and run [slots](examples/slots.rs). It uses `n=N`, directly
encodes two slot vectors, multiplies them and rotates each row by one under
an encrypted automorphism key. Two requests reuse setup, prepared operations
and evaluation outputs; `encode`, `decode`, encryption and recovery allocate
their results. Advanced examples and benches use `*_to` with reusable scratch.

```sh
cargo run -p primus_bfv --example slots --features batching
```

`context.batching_encoder()` prepares the existing `BatchingEncoder` from N/t;
it owns one plaintext NTT table and is not cached or cloned by the context.
Use `client.row_rotation_key(level,&encoder,steps,config,rng)` for a signed
left rotation, with negative steps rotating right and wrapping within each row.
`row_swap_key` exchanges the rows. Bind either key with
`BfvAutomorphism::try_new(&context,&key)`, which derives its level from the key.
Encoder modulus/capacity mismatches are rejected before random sampling.

The advanced [subring slots](examples/subring_slots.rs) and
[leveled slots](examples/leveled_slots.rs) examples embed `n<N` plaintexts
while retaining full-N secrets and ciphertexts. These explicit encoders can
support `n<N` even when full-N batching is unavailable for the chosen plaintext
modulus. Unused slots and off-stride padding are zero. Generic
`automorphism_key` and the encoder's exponent methods remain available for
explicit polynomial substitutions.

## Evaluation and levels

`BfvEvaluator::new(&context,level)` handles ciphertext add/subtract/negate and
plaintext add/multiply. Plaintext operations choose `PlaintextEmbedding`
explicitly: addition applies delta once; multiplication uses the **unscaled**
plaintext lift. Canonical reduction modulo t can add encoding drift because
`delta*t` need not equal Q.

Use `BfvContext::try_with_levels(parameters,level_count)` to prepare a prefix
chain. The count includes level zero; level l removes the last l primes.
`BfvModulusSwitch::new(&context,source_level).switch_to` drops one final prime
using exact coefficientwise nearest rounding. Each destination has its own
codec and must satisfy its complete error bound.

Native role keys implement relinearization, source-to-recipient key switching
and encrypted automorphisms. Their prepared constructors take `(&context,&key)`
and derive the bound level. Key generation, unkeyed linear evaluation, prime drops
and recovery still select their actual level explicitly. Generate a fresh key for
every actual level used.
BFV key columns have phase `g_j*h+e_j`; truncated decomposition residual and key
noise both consume recovery margin. The maximum digit count need not remove
all radix remainder bits. The complete [leveled coefficient](examples/leveled_coefficients.rs)
and [leveled slot](examples/leveled_slots.rs) examples combine multiplication,
square, rotation, Alice→Bob switching and two drops.

## Collective keys and one-use raw lookup

`BfvCollectivePublicKey`, `BfvCollectiveSwitchingKey` and
`BfvCollectiveAutomorphismKey` accept one owner's individual shares per
`contribute` call. `aggregate(expected)` allocates a public sum; `add` checks
the actual local setup instance and count, and `finalize` consumes a complete
sum into the ordinary native role key. Transport uses `common_mask`,
`as_residues` and checked `try_import_contribution`; no private key columns
are public. This first construction requires exact CBD1 shares and CBD21
errors. Imported secret distribution metadata does not prove CBD1 coefficients.

`BfvCollectiveRelinearization::start` returns a public first message and a
noncloneable, erasing private state. Freeze the complete first-round sum with
`freeze_round1`, then consume each state with `round2`. The frozen result's
second accumulator must use the same roster size. Finalization includes all
cross terms of `(Σs_i)²`; it never accepts a vector of private shares or
constructs the aggregate secret. The calling protocol authenticates owners,
rejects duplicates, binds source/target/session identities and prevents reuse.
Arithmetic count checks alone do not establish those properties.

Source/target switching uses one actual context; `contribute` still receives
the two distinct share owners. Matching parameters in another context are not
accepted as proof of the same transform owner.

For a separately sampled fresh lookup setup, use `finalize_lookup` and
`BfvFreshLookupKey::prepare()`, which derives the context from the finalized key.
`apply_to` consumes this prepared key and a
checked `BfvRawQuadraticAggregate`, applies one **unscaled** relin and performs
no ordinary BFV scale-and-round. Key errors and ephemeral values must be
independent of selector inputs, including indirect public-key/transcript seed
dependencies. Ordinary `BfvQuadraticCiphertext` remains the scaled-input type.

`client.partial_phase_to` writes only `c1*s_i`, without c0, decoding or privacy
noise. The protocol must consume its opening authorization and add a complete
wide-integer flood before releasing this phase. `client.try_embed_secret`
checks and embeds only its own CBD1 target share as `s_i(X²)` for split-switch;
it does not perform the subsequent even/odd ciphertext split.

## Multiplication backends and recovery

The default `Exact` backend retains centered **integer** negacyclic component products before
exactly computing `round(t*T_i/Q) mod Q`. The RNS NTT implementation prepares an
auxiliary basis P satisfying `P>N*Q`; reducing the tensor modulo Q before scaling
would lose required integer multiples. It uses exact CRT and quotient recovery,
without floating-point rounding. The independent integer schoolbook algorithm
and raw tensor inspection remain private mathematical validation machinery.
They do not add public representation accessors for tests or benchmarks.

Advanced callers can choose P with
`BfvMultiplication::try_with_auxiliary_moduli(context,key,&primes)`, or use
`BfvMultiplier` followed by `BfvRelinearizer` when the already-scaled quadratic
intermediate is needed. Construction checks capacity, coprimality and NTT
compatibility; actual primality of supplied primes remains a caller precondition.
The [evaluation contract](../../guides/development/bfv-evaluation.md) derives
integer lift bounds, exact quotient recovery and the complete phase error.

For the optimized backend, keep the same request and choose
`BfvMultiplication::try_with_backend(context,key,BfvMultiplicationBackend::HpsPOverQ)`.
It performs one-sided P/Q prescaling, a QP tensor and exact t/P scale-and-round;
its bounded residual and centered wrap are part of the evaluated error.
`try_with_backend_and_auxiliary_moduli` selects an explicit P under that backend's
own condition (`P>2*#Q`, without `P>NQ`). Automatic P reserves a bound for the
prescaling residual using the sampler's supported secret magnitude; it does not
certify the complete circuit. Only the selected backend owns P/tables/scratch,
and `backend()`/`auxiliary_moduli()` describe that resource. Both backends reuse
the same native relinearization and allocate nothing online. The default stays
`Exact`; see the [algorithm and error contract](../../guides/development/bfv-evaluation.md#hpspoverq-backend)
and [complete-request comparison](../../guides/performance/bfv-hps-over-q.md).

The codec recovers the exact message **within its recovery bound**. It is not an
exact-rounding oracle for arbitrary phases. For `delta*m+e`, a sufficient
condition is `abs(t*e-(Q%t)*m)/Q+k/gamma<1/2`, where k is the Q prime count.
`codec(level).validate_noise_bound` checks a conservative all-message bound.
`try_coefficients` uses decoder modulus `gamma=2^61-1` and requires `t<gamma`;
`try_new` selects gamma, and `try_with_error_distribution` also selects the error
law. Constructors check the codec conditions and sufficient fresh private
recovery using the complete sampler support. They do not prove a security level,
public encryption recovery or evaluated recovery. Include public-key noise,
fixed-delta drift, all evaluation terms and every drop's rounding error.

After an explicit scheme bridge in another owner's actual NTT table,
`BfvModulusSwitch::try_from_parts` borrows that table and checked adjacent
ordered bases to prepare the same rounded kernel without a second BFV context.
The enclosing protocol retains the original request/secret authorization and
accounts for component rounding and message-lift drift.

## Advanced explicit workflows

[Explicit coefficients](examples/explicit_coefficients.rs) demonstrates borrowed
`BfvSecretKeyContext`, an explicit `U64DcrtTable`, reusable outputs and
`BfvDecryptWorkspace`. These are useful when another workflow already owns the
transformed secret/table. `size()` owns geometry, `base_q()` basis arithmetic,
`codec()` scaling/recovery constants and `encryption_parameters()` samplers.

Raw GLWE retains `[a,b]` and phase `b-a*s`. `write_raw_glwe_to` writes
`[a=-c1,b=c0]`; `set_from_raw_glwe` imports `[c0=b,c1=-a]`. Both copy/negate
canonical residues without allocation or NTT. The
[Hybrid-RNS example](examples/hybrid_rns_key_switch.rs) consumes these bridges
because its switching/GGSW keys retain raw semantics. `gadget_parameters`
prepares codec-free decomposition weights for these real raw consumers.
The explicit secret/public encryption bindings also accept coefficient-domain CRT
inputs: `encrypt_plaintext_lift_crt_to` takes an **unscaled** canonical lift and
applies delta once; `encrypt_encoded_crt_to` takes an **already-scaled** phase
and never applies delta. Passing codec output to the lift entry would scale it
twice. CRT limbs use modulus-major Q order.

Signs and noise contributions are explained in
[RNS phase conventions](../../guides/development/rns-phase-conventions.md).

## Resources and checks

Contexts own Q tables, samplers and the requested codecs. Clients own one
highest-level transformed secret and recovery workspace; lower recovery borrows
their prefixes. Prepared operations borrow immutable context/key resources and
own mutable scratch. Independent concurrent requests use separate mutable
operation owners. Prepared `*_to` and `*_assign` calls allocate no temporary
storage; constructors and allocating encryption/decryption allocate. Secret and
ephemeral/recovery scratch are erased on drop. `encryptor.zeroize()` and
`Zeroize::zeroize(&mut decrypt_workspace)` preserve allocation and geometry.

Encryption validates complete lengths and canonical plaintexts before RNG
consumption or writes. Evaluator plaintext entries validate before writes.
Ciphertexts carry storage rather than authenticated level, secret or transform
identity. Callers must use the actual level, canonical NTT residues, agreed
roots/order and actual coefficient secret. Equal lengths/moduli do not establish
these identities. Optimized Q primes must be NTT-compatible and below `2^62`.
Per-method rustdoc owns precise contracts and partial-write behavior.

Default features are empty. `simd` forwards to shared backends and follows their
nightly requirements.
Runtime NTT intrinsic dispatch is independent of this Cargo feature; disabling
`simd` does not force scalar NTT. See the [feature boundary](../../guides/development/testing.md#features-与独立消费者).

```sh
cargo check -p primus_bfv --all-targets --features batching
cargo test -p primus_bfv --lib --tests --features batching
cargo clippy -p primus_bfv --all-targets --features batching -- -D warnings
cargo run -p primus_bfv --example explicit_coefficients
cargo run -p primus_bfv --example hybrid_rns_key_switch
cargo run -p primus_bfv --example leveled_coefficients
cargo run -p primus_bfv --example leveled_slots --features batching
cargo bench -p primus_bfv --bench multiplication --features batching
```

Small tests use independent direct-DFT, schoolbook and integer-rounding oracles;
private representation checks stay within private test modules. They cover
phases, dense products, boundaries, raw bridges, error checks, workspace reuse/
erasure and allocation contracts. Criterion measures public prepared operations
and complete fresh requests; setup stays outside timing. Historical measurements
and their source/workload limits are in the
[performance report](../../guides/performance/bfv-multiplication.md).

Advanced owner handoffs can consume `client.into_secret_key()` and pass the
single transformed allocation to `BfvClient::try_from_secret_key` in another
validated role. Recovery scratch is dropped and erased; the source client is
consumed. Complete geometry and actual NTT roots/order must match before a
cross-scheme move. This transfers ownership and does not clone a private share.
