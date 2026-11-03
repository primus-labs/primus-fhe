# primus_bfv

English | [简体中文](README.zh_CN.md)

BFV coefficient and slot encryption/evaluation with native components `[c0,c1]`
and phase `c0+c1*s=delta*lift(m)+e`, where `delta=floor(Q/t)`. The rank-one
backend uses `u64` residues, `BarrettModulus<u64>` and `U64DcrtTable`; Q can
exceed 64 bits. Arithmetic, NTTs, samplers, secret storage and encoding are
shared with the lower crates. Optional `batching` adds shared slot encoding.

## Coefficient workflow

Start with [coefficients](examples/coefficients.rs): public encryption, one
ciphertext multiplication and coefficient recovery.

```sh
cargo run -p primus_bfv --example coefficients
```

1. Construct `BfvParameters::try_coefficients(N,t,&Q,secret_law,sigma)` and move
   it into `BfvContext::try_new(parameters)`.
2. Generate `BfvClient::generate(&context,rng)`, create `client.public_key(rng)`
   and bind `context.public_key_encryptor(&public_key)`.
3. Encrypt a polynomial with `encryptor.encrypt_centered(&message,rng)`.
4. Generate `client.relinearization_key(level,config,rng)` and prepare
   `BfvMultiplication::try_new(&context,&relin_key)` once. Its `multiply_to`
   and `square_to` return ordinary degree-one ciphertexts; `square_assign`
   overwrites the input. Internal scale/relinearization scratch is reused.
5. Recover the result with `client.decrypt(&ciphertext,level)`.

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
an encrypted automorphism key.

```sh
cargo run -p primus_bfv --example slots --features batching
```

`BatchingEncoder` maps slots into two ±5^j rows. Use its `rotation_exponent`
and `row_swap_exponent` with `BfvAutomorphism`; these execute ciphertext
operations. The advanced [subring slots](examples/subring_slots.rs) and
[leveled slots](examples/leveled_slots.rs) examples embed `n<N` plaintexts
while retaining full-N secrets and ciphertexts. Unused slots and off-stride
padding are zero.

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
and encrypted automorphisms. Generate a fresh key for every actual level used.
BFV key columns have phase `g_j*h+e_j`; truncated decomposition residual and key
noise both consume recovery margin. The maximum digit count need not remove
all radix remainder bits. The complete [leveled coefficient](examples/leveled_coefficients.rs)
and [leveled slot](examples/leveled_slots.rs) examples combine multiplication,
square, rotation, Alice→Bob switching and two drops.

## Exact multiplication and recovery

Multiplication retains centered **integer** negacyclic component products before
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
