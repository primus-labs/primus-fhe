# primus_bgv

English | [简体中文](README.zh_CN.md)

Leveled BGV with rank-one `u64` RNS. Native ciphertexts store `[c0,c1]`
with phase `c0+c1*s`, p-scaled error and an invertible message correction
factor. Every ciphertext prime is coprime to the plaintext modulus p.

## Start with coefficients or slots

```sh
cargo run -p primus_bgv --example coefficients
cargo run -p primus_bgv --example slots --features batching
```

[Coefficients](examples/coefficients.rs) publicly encrypts a polynomial, adds a
plaintext constant, scales it and recovers the result. The [slots
example](examples/slots.rs) applies the same operations to packed values.

1. Create `BgvParameters` and move them into `BgvContext`.
2. Generate a `BgvClient` and its public key. Bind the public key to an encryptor
   with `context.public_key_encryptor`.
3. Allocate output with `context.new_ciphertext(level)`. Reuse a
   `BgvEvaluator` for plaintext operations and recover with `client.decrypt`
   or `client.decrypt_to`.

Encryption takes N canonical coefficients in `[0,p)`. For full-ring slots, use
`context.batching_encoder()` with prime p ≡ 1 (mod 2N), encode into a plaintext
polynomial and decode after decryption. Example parameters demonstrate
functionality.

## Advanced workflows

| Example | Task |
| --- | --- |
| [ciphertext_multiplication](examples/ciphertext_multiplication.rs) | Reuse a relinearization key and a prepared multiplier. Append `-- --hybrid` for partitioned QP keys. |
| [leveled_coefficients](examples/leveled_coefficients.rs) | Admit a circuit, evaluate on encrypted coefficients, switch secrets and recover after two drops. Supports `-- --hybrid`. |
| [leveled_slots](examples/leveled_slots.rs) | Multiply encrypted subring slots and apply row rotation and row swap after one drop. Requires `batching`. |
| [collective](examples/collective.rs) | Combine public-key contributions and run two-round relinearization setup. |
| [public_worker](examples/public_worker.rs) | Export public material for evaluation in a separate worker context. |

```sh
cargo run -p primus_bgv --example leveled_coefficients -- --hybrid
cargo run -p primus_bgv --example leveled_slots --features batching
cargo run -p primus_bgv --example public_worker
```

`evaluation` contains prepared operations, `keys` contains key configuration
and `collective` contains shared key contributions.
[Native Hybrid and collective key setup](../../guides/development/native-hybrid-keys.md)

## Generate parameters and admit a declared circuit

`planning::BgvParameterRequest` generates NTT primes from explicitly chosen
resources and sampler laws. `BgvCircuitPlan` checks the arithmetic budget for a
declared ordinary circuit and provides the admitted key configuration for each
level. `security_inputs()` exports the actual numerical domains for a separate
security analysis, including Hybrid QP where selected. The plan's security
status remains `NotEvaluated`. Collective and raw protocols require their own
budgets. [Circuit budgets](../../guides/development/bgv-evaluation.md#public-static-circuit-budgets) ·
[Parameter and security reference](../../guides/development/ordinary-parameter-budgets.md)

## Levels, slots and numerical contracts

Level zero uses all Q primes. Each subsequent level drops the last prime.
Generate role keys at their actual levels. Recovery uses the ciphertext's level
and correction factor, which can differ between ciphertexts at the same level.
Pass whole ciphertexts to evaluators so the factor stays with the residues.
The intended integer phase must remain within the centered modulus interval
at every recovery. [BGV evaluation](../../guides/development/bgv-evaluation.md) ·
[RNS phase conventions](../../guides/development/rns-phase-conventions.md)

Coefficient p may be composite. Slots need a prime p ≡ 1 (mod 2n) for the
chosen plaintext ring n. For a subring, `embed_to` and `extract_to` map between
its plaintexts and the full ring. Positive row rotations move left within
each row. Row swap exchanges the two rows.
[Batching encoder](../primus_encoding/README.md)

Prepared operations borrow the context and keys and have mutable scratch.
Use separate prepared operations for concurrent requests. Explicit raw
interop requires the actual basis, transform, secret and correction factor.
[Context binding and raw imports](../../guides/development/scheme-context-binding.md)

## Collective and opening

The collective example demonstrates local key arithmetic. Applications own
authentication, roster and round binding, one-use state, and privacy flooding
before releasing partial phases. Authenticate the ciphertext's factor together
with its residues. [Collective and opening contracts](../../guides/development/scheme-context-binding.md#collective-与安全-opening-的分工)

## Features and benchmarks

Default features are empty. `batching` enables slots, `parallel` enables DCRT
limb scheduling and `simd` forwards nightly SIMD support. See the
[feature and validation guide](../../guides/development/testing.md).

```sh
cargo bench -p primus_bgv --bench leveled --features batching
```

For timing endpoints and historical workload limits, see the
[performance guide](../../guides/performance/README.md#bfv-and-bgv).

## Public storage

Use `to_public_bytes` / `from_public_bytes` for public contexts and the context's
`export_*` / `import_*` methods for ciphertexts and role keys. The ciphertext's
correction factor is preserved. Set `PublicObjectLimits` for the receiver and
authenticate the bytes together with their application role and identities.
The client keeps the secret locally.
[Public storage contract](../../guides/development/public-storage.md) ·
[Public worker example](examples/public_worker.rs)
