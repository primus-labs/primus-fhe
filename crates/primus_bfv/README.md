# primus_bfv

English | [简体中文](README.zh_CN.md)

BFV coefficient and slot encryption/evaluation over rank-one `u64` RNS.
Ciphertexts store `[c0,c1]` with phase `c0+c1*s=delta*lift(m)+e`, where
`delta=floor(Q/t)`. Each residue uses `u64`; the product Q may exceed 64 bits.
Arithmetic, NTT, sampling, secret storage and encoding reuse the lower crates.

## Coefficients and slots

Start with [coefficients](examples/coefficients.rs). It publicly encrypts a
polynomial, adds a plaintext constant, multiplies by a plaintext scalar and
recovers coefficients. Two requests reuse one setup; no evaluation key is needed.

```sh
cargo run -p primus_bfv --example coefficients
cargo run -p primus_bfv --example slots --features batching
```

Both examples follow the same chain:

1. Build `BfvParameters::try_coefficients(N,t,&Q,secret_law,sigma)` and move it
   into `BfvContext::try_new(parameters)`.
2. Generate `BfvClient::generate(&context,rng)`, retain `client.public_key(rng)`
   and bind `context.public_key_encryptor(&public_key)`.
3. Allocate plaintexts and outputs with `context.new_plaintext()` and
   `context.new_ciphertext(level)`. Prepare `BfvEvaluator::new(&context,level)`.
4. Encrypt, use `add_plain_to` / `mul_plain_to` with `PlaintextEmbedding`, then
   recover with `client.decrypt(&ciphertext)`, which uses the bound level. Reuse
   setup and outputs for the next request, with fresh encryption coins.

[Slots](examples/slots.rs) adds one `context.batching_encoder()` and uses n=N.
`encode_to` writes directly into the context's plaintext polynomial; `decode`
recovers slots after decryption. The encoder owns its plaintext NTT table, so
retain it across requests. Basic examples use allocating encryption/recovery
conveniences; prepared `*_to` calls support reusable caller-owned outputs.
Their small parameters demonstrate functionality and are not security presets.
Full-ring packing needs a plaintext prime t≡1 mod 2N. The subring examples use
the plaintext ring n<N while retaining full-N secrets and ciphertexts.

## Choose an advanced workflow

| Need | Entry point and added resource |
| --- | --- |
| Ciphertext multiplication | [ciphertext_multiplication](examples/ciphertext_multiplication.rs): one relinearization key and `BfvMultiplication`, reused for two requests |
| Native Hybrid keys | The same example accepts `-- --hybrid`; explicit key P and partitioned QP replace the radix key backend |
| Levels, automorphism and secret change | [leveled_coefficients](examples/leveled_coefficients.rs): multiply/square, X→X⁵, Alice→Bob switching and two drops |
| Plaintext subring n<N | [subring_slots](examples/subring_slots.rs): embed/extract with full-N secrets/ciphertexts and zero spare slots |
| Encrypted slot operations | [leveled_slots](examples/leveled_slots.rs): multiply/square, row rotation/swap, secret change and two drops in a plaintext subring |
| Temporary working basis | [working_basis](examples/working_basis.rs): a checked ordinary three-square chain retaining external level zero; `--radix` selects radix keys |
| Borrow an existing secret | [explicit_coefficients](examples/explicit_coefficients.rs): `BfvSecretKeyContext::try_new(&key,&context)` and explicit erasing recovery scratch |
| Raw GLWE interoperability | [hybrid_rns_key_switch](examples/hybrid_rns_key_switch.rs): explicit phase conversion for raw switching/GGSW consumers |

```sh
cargo run -p primus_bfv --example ciphertext_multiplication
cargo run -p primus_bfv --example ciphertext_multiplication -- --hybrid
cargo run -p primus_bfv --example leveled_slots --features batching
```

Role-key operations take `(&context,&key)` and derive their level from that key;
key generation, linear evaluation and prime drop select their actual level
explicitly. Ordinary recovery reads the ciphertext's bound level. `try_with_levels(parameters,count)` includes level zero;
level l omits the last l primes. Generate keys for each actual level used.
A positive `row_rotation_key` step rotates left within each row, a negative one
rotates right; `row_swap_key` exchanges the two rows. Generic polynomial
substitutions remain available through `automorphism_key`.

For repeated roles, prepare `context.radix_key_parameters(level,config)` or
`context.hybrid_key_parameters(level,decomposition_count,&key_p)` once and share
its `Arc`. Shared numerical metadata alone does not prove an imported secret or transform's provenance.
Key P enlarges the evaluation-key modulus to QP and needs its own error/security
budget. It is separate from BFV multiplication's computation-only P. See the
[native Hybrid contract](../../guides/development/native-hybrid-keys.md).

## Numerical and ownership contracts

Encryption takes exactly N canonical values in `[0,t)`. Unsigned lifts m to m;
centered uses `[-floor(t/2),ceil(t/2))`. Recovery returns canonical coefficients.
Plaintext addition applies delta once; plaintext multiplication uses an unscaled
lift. Since `delta*t` need not equal Q, reduction modulo t introduces encoding
drift that belongs in the complete error bound.

`BfvMultiplication` combines scale-and-round with native relinearization and
returns degree-one outputs. Its default `Exact` backend retains integer tensors
using computation P>NQ. Explicit `HpsPOverQ` uses asymmetric prescaling and its
own P>2·#Q condition/residual; selecting a Hybrid key does not select HPS.
The [evaluation contract](../../guides/development/bfv-evaluation.md) owns these
algorithms, truncated-radix residuals, exact rounded prime drops and error bounds.
`BfvMultiplier` / `BfvRelinearizer` preserve an explicitly staged scaled quadratic
workflow. The [working-basis contract](../../guides/development/bfv-working-basis.md)
covers finite ordinary CBD1/CBD21 profiles; collective or raw SSLE needs separate
accounting.

The codec is exact within its recovery bound, not an arbitrary-phase rounding
oracle. `try_coefficients` selects gamma=2⁶¹−1 and requires t<gamma; `try_new`
selects gamma explicitly and `try_with_error_distribution` selects the error law.
Construction checks sufficient fresh private recovery, not public/evaluated
recovery or a security level. Include public-key noise, delta drift, evaluation,
key-switch residuals and every drop. Supplied Q/P primes must actually be suitable
primes; NTT rootability does not prove primality. Optimized q_i must be below 2⁶².

Collective plans borrow individual `DcrtGlweSecretKey<u64>` shares and require
exact CBD1/CBD21 laws. Protocol callers authenticate roster/session/role and
actual NTT/secret provenance; count and distribution metadata cannot prove them.
Two-round private states are consuming and erasing. Fresh lookup uses a separate
`BfvFreshLookupKey` and `BfvRawQuadraticAggregate` for one **unscaled** relin,
without ordinary BFV scale-and-round; its noise/ephemeral must be independent of
selector inputs, including indirect seed dependencies. `partial_phase_to` releases
only c1*s_i and requires protocol authorization plus complete privacy flooding
before publication. See [collective and lookup contracts](../../guides/development/native-hybrid-keys.md#collective-roles-and-fresh-lookup).

Raw GLWE has phase b−a*s: the explicit bridges map `[c0,c1]` to `[a=−c1,b=c0]`
and back without NTT. Advanced CRT inputs keep two meanings:
`encrypt_plaintext_lift_crt_to` applies delta once to an unscaled lift;
`encrypt_encoded_crt_to` accepts an already-scaled phase. Both use modulus-major Q
order. Sign and representation details are in [RNS phase conventions](../../guides/development/rns-phase-conventions.md)
and each method's rustdoc.

## Resources and features

Context owns samplers/codecs and immutable Q tables. Paired contexts can share
actual tables through `shared_table()` / `try_with_table`, which checks N/ordered Q.
Clients own one transformed secret and recovery scratch; lower recovery borrows
prefixes. Prepared operations borrow context/key resources and own mutable scratch;
independent concurrent requests use separate operation owners. Prepared `*_to` /
`*_assign` calls allocate no temporary storage. Secret, ephemeral and recovery
scratch are erased on drop. `into_secret_key` consumes a client for a checked
owner handoff; it never clones a private share.

Public coefficient inputs are checked before RNG consumption or writes.
Context-created ciphertexts, their clones and views retain that local context and
level. Prepared keys must belong to the same context; bound foreign-context or
wrong-level inputs/outputs reject before writes. `client.decrypt(&ciphertext)`
uses this binding. It does not prove the actual secret relationship or authenticate
residues modified through `AsMut`. Explicit `from_raw` / `zero_raw` containers and
`decrypt_at_level` / `decrypt_at_level_to` retain the advanced caller contract.
`context.try_bind_ciphertext(raw,level)` checks storage and canonicality once;
the caller still attests its actual transform and secret.
See [context, level and raw interoperability](../../guides/development/scheme-context-binding.md).
Per-method rustdoc specifies exact input, scratch and partial-write contracts.

Default features are empty. `batching` enables shared slot encoding. `simd`
forwards the shared nightly backends; runtime NTT intrinsic dispatch is separate,
so disabling `simd` does not force scalar NTT. See the [feature boundary](../../guides/development/testing.md#features-与独立消费者).

`parallel` enables bounded DCRT prefix forward/inverse NTT scheduling in the
connected key-generation and gadget-product paths. Each prefix with N≥4096 and
at least two limbs uses at most four contiguous tasks; bound total pool threads
with `RAYON_NUM_THREADS` or `ThreadPool::install`. It is off by default, leaving
this NTT path serial without pool initialization. Random sampling stays serial.

## Checks

```sh
cargo check -p primus_bfv --all-targets --features batching
cargo test -p primus_bfv --lib --tests --features batching
cargo clippy -p primus_bfv --all-targets --features batching -- -D warnings
```

Tests retain independent DFT/schoolbook/integer-rounding oracles and focused
binding, recovery, dirty-scratch, erasure and allocation boundaries. Crate-local
benches measure explicit prepared workloads; setup stays outside timing. Their
historical source/workload limits are in the [performance report](../../guides/performance/bfv-multiplication.md).
