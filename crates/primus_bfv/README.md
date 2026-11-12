# primus_bfv

English | [简体中文](README.zh_CN.md)

BFV coefficient and slot evaluation over rank-one `u64` RNS. Native ciphertexts
store `[c0,c1]` with phase `c0+c1*s` and message scale `floor(Q/t)`. Each residue
fits one word and the full modulus Q can span multiple words.

## Coefficients and slots

```sh
cargo run -p primus_bfv --example coefficients
cargo run -p primus_bfv --example slots --features batching
```

[Coefficients](examples/coefficients.rs) publicly encrypts a polynomial, adds a
plaintext constant, scales it and recovers the result. The [slots
example](examples/slots.rs) applies the same operations to packed values.

1. Create `BfvParameters` and move them into `BfvContext`.
2. Generate a `BfvClient` and its public key. Bind the public key to an encryptor
   with `context.public_key_encryptor`.
3. Allocate output with `context.new_ciphertext(level)`. Reuse a
   `BfvEvaluator` for plaintext operations and recover with `client.decrypt`
   or `client.decrypt_to`.

Encryption takes N canonical coefficients in `[0,t)`. For full-ring slots, use
`context.batching_encoder()` with prime t ≡ 1 (mod 2N), encode into a plaintext
polynomial and decode after decryption. Example parameters demonstrate
functionality.

## Choose an advanced workflow

| Example | Task |
| --- | --- |
| [ciphertext_multiplication](examples/ciphertext_multiplication.rs) | Reuse a relinearization key and a prepared multiplier. Append `-- --hybrid` for partitioned QP keys. |
| [leveled_coefficients](examples/leveled_coefficients.rs) | Multiply and square, switch to a new secret, and decrypt after two prime drops. |
| [subring_slots](examples/subring_slots.rs) | Pack a smaller plaintext ring, keep full-ring ciphertexts and recover after a drop. Requires `batching`. |
| [working_basis](examples/working_basis.rs) | Admit a square chain that uses temporary bases at external level zero. Append `-- --radix` for radix keys. |
| [explicit_coefficients](examples/explicit_coefficients.rs) | Borrow an existing secret and reuse an explicit recovery workspace. |
| [hybrid_rns_key_switch](examples/hybrid_rns_key_switch.rs) | Convert the phase convention for raw RNS GLWE key switching and GGSW operations. |

```sh
cargo run -p primus_bfv --example ciphertext_multiplication -- --hybrid
cargo run -p primus_bfv --example subring_slots --features batching
cargo run --release -p primus_bfv --example working_basis
```

`evaluation` contains prepared operations, `keys` contains key configuration,
and `planning` contains ordinary arithmetic budgets. Generate role keys at
their actual ciphertext levels. For packed automorphisms, see the
[batching encoder](../primus_encoding/README.md) and the [BGV row operations
example](../primus_bgv/examples/leveled_slots.rs).

## Numerical and ownership contracts

Level zero uses all Q primes. Each level drops the last prime of the previous
level using nearest rounding. Ciphertexts allocated by a context carry that
context and level. Prepared operations borrow their context and keys and have
mutable scratch. Use separate prepared operations for concurrent requests.
[Context binding and raw imports](../../guides/development/scheme-context-binding.md)

Choose distinct NTT primes for Q. The default coefficient constructor selects
decoder gamma = 2⁶¹−1 and requires t < gamma. Parameter construction checks
fresh private recovery. Public and evaluated ciphertexts need their own
complete phase bounds. `BfvMultiplication` defaults to Exact and also supports
HPSPOVERQ. The multiplication backend and Radix/Hybrid key backend are
independent choices. [Evaluation and recovery bounds](../../guides/development/bfv-evaluation.md) ·
[Working basis and arithmetic admission](../../guides/development/bfv-working-basis.md) ·
[Parameter and security reference](../../guides/development/ordinary-parameter-budgets.md)

Collective setup, fresh lookup and raw opening have separate role and noise
requirements. Raw GLWE stores a different mask sign from native BFV. Use the
explicit phase conversion when crossing this boundary.
[Native Hybrid and collective keys](../../guides/development/native-hybrid-keys.md) ·
[RNS phase conventions](../../guides/development/rns-phase-conventions.md)

## Features and benchmarks

Default features are empty. `batching` enables slots, `parallel` enables DCRT
limb scheduling and `simd` forwards nightly SIMD support. See the
[feature and validation guide](../../guides/development/testing.md).

```sh
cargo bench -p primus_bfv --bench multiplication --features batching
```

For timing endpoints and historical workload limits, see the
[performance guide](../../guides/performance/README.md#bfv-and-bgv).

## Public storage

Use `to_public_bytes` / `from_public_bytes` for public contexts and the context's
`export_*` / `import_*` methods for ciphertexts and role keys. Set
`PublicObjectLimits` for the receiver and authenticate the bytes together with
their application role and identities. The client keeps the secret locally.
[Public storage contract](../../guides/development/public-storage.md) ·
[Public worker example](../primus_bgv/examples/public_worker.rs)
