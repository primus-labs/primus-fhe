# primus_distr

English | [简体中文](README.zh_CN.md)

`primus_distr` provides the discrete probability distributions and batch sampling helpers used by [Primus FHE](../../README.md). It covers binary and ternary secrets, centered discrete Gaussian noise, modular and signed output representations, CRT batch layouts, and statistical diagnostics.

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, sampling algorithms, and numerical contracts are unstable and may change incompatibly at any time.

## Main distributions

| Type | Output and role |
| --- | --- |
| `BinaryDistr` | Uniform samples from `{0, 1}` |
| `SparseTernaryDistr<T>` | Samples from `{0, 1, -1}` with probabilities `1/2`, `1/4`, and `1/4`; the caller supplies the representation of `-1` |
| `DiscreteGaussian<T>` | Centered Gaussian samples encoded as canonical unsigned residues modulo a caller-supplied modulus |
| `SignedDiscreteGaussian<T>` | Centered Gaussian samples represented directly by a signed integer type |
| `CDTSampler<T>` / `SignedCDTSampler<T>` | Explicit portable 64-bit cumulative-distribution-table backends |
| `DiscreteZiggurat<T>` / `SignedDiscreteZiggurat<T>` | Explicit discrete Ziggurat backends for larger supports |

The scalar sampler types above implement `rand::distr::Distribution`. Batch helpers require an RNG implementing both `rand::Rng` and `rand::CryptoRng`.

## Secret-key distribution parameters

`SecretKeyDistr` describes a complete binary, ternary, fixed-weight or Gaussian key; it is not a scalar sampler. Use `binary(one_probability)` or `ternary(negative_one_probability, one_probability)` for custom probabilities. Each probability must be finite and in `[0, 1]`, and the ternary sum must not exceed one. Cryptosystems choose which variants they support.

| Constructor | Distribution |
| --- | --- |
| `fixed_hamming_weight_binary(length, weight)` | Exactly `weight` ones at uniformly selected positions |
| `fixed_hamming_weight_ternary(length, weight)` | Exactly `weight` nonzero positions with independent uniform signs |
| `fixed_composition_ternary(length, negative_weight, positive_weight)` | Exact separate counts of negative and positive ones |

Weights apply to the complete logical key. Constructors reject excessive weights and sum overflow, but do not retain the length; sampling checks the actual output length before writing or drawing randomness.

Prepare `SecretKeySampler<T>` with `try_new(distribution)` (fallible) or `new(distribution)` (panicking). Use `sample_signed` / `sample_signed_to` for `T::SignedInteger` output, or `sample_encoded` / `sample_encoded_to` for canonical residues. The `_to` methods overwrite caller storage without allocating.

`maximum_magnitude()` gives an inclusive sample bound; Gaussian support must fit the signed companion type, while binary and ternary return one. Before encoded sampling, require `modulus_minus_one >= maximum_magnitude()`; `T::MAX` denotes the native modulus. `validate_modulus` checks this condition without sampling. The sampler does not store a modulus. Full contracts and errors are in the [sampler API](src/secret_key_sampler.rs).

Custom ternary probabilities are rounded down to multiples of `2^-64`, with total nonzero mass capped at one for floating-point boundary rounding. RNG consumption and seeded outputs may change across versions; empty whole-key sampling is not guaranteed to consume no randomness.

## Example

```rust
use primus_distr::{SignedDiscreteGaussian, sample_crt_gaussian_values};
use rand::{SeedableRng, rngs::StdRng};

let gaussian = SignedDiscreteGaussian::<i64>::new(3.2).unwrap();
let moduli = [97_u64, 193];
let poly_length = 8;
let mut rng = StdRng::seed_from_u64(7);

let samples = sample_crt_gaussian_values(
    poly_length,
    &moduli,
    &gaussian,
    &mut rng,
);

assert_eq!(samples.len(), poly_length * moduli.len());
assert!(samples[..poly_length].iter().all(|&x| x < moduli[0]));
assert!(samples[poly_length..].iter().all(|&x| x < moduli[1]));
```

## Gaussian construction and representations

The `DiscreteGaussian` and `SignedDiscreteGaussian` facades use a default tail cut of 12 standard deviations. Construction rejects non-finite parameters, standard deviations below `MIN_STANDARD_DEVIATION`, supports that cannot be represented by the selected output type, and modular supports that do not fit below the supplied modulus.

The facades select the portable CDT backend when the truncated support fits its 255-magnitude table and otherwise use the Ziggurat backend. Construct an explicit `*CDTSampler` or `*Ziggurat` when the tail cut or backend must be chosen directly.

`DiscreteGaussian::new(sigma, modulus_minus_one)` returns values in `[0, modulus_minus_one]`. A negative logical sample `-x` is encoded as `modulus_minus_one - x + 1`. `SignedDiscreteGaussian::new(sigma)` instead returns positive, zero, and negative values directly.

## Batch sampling

`DiscreteGaussian` and `SignedDiscreteGaussian` provide allocating `sample_vec(length, rng)` and non-allocating `sample_to(output, rng)`. Their outputs and RNG consumption match repeated scalar `Distribution::sample` calls; empty Gaussian batches consume no randomness. Vector helpers likewise offer allocating and `_to` forms for binary, ternary, fixed-weight, uniform and Gaussian distributions.

CRT batches use **modulus-major** layout: for `N` coefficients and `k` moduli, the output contains `k * N` elements:

```text
[a_0 mod q_0, ..., a_(N-1) mod q_0,
 a_0 mod q_1, ..., a_(N-1) mod q_1,
 ...]
```

`sample_crt_uniform_binary_values*`, `sample_crt_sparse_ternary_values*` and `sample_crt_gaussian_values*` encode the same logical coefficient in every component. `sample_crt_uniform_values*` instead samples independently under each component's uniform distribution.

Provide complete blocks with the exact component count and a nonzero length for nonempty batches. CRT uniform-binary sampling specifically requires at least one nonempty block; incomplete blocks are not filled. Other helpers' empty-input and length conditions are documented in the [CRT sampling API](src/common/crt.rs).

CRT Gaussian helpers do not check whether each modulus can encode the complete truncated support. For standard deviation `sigma` and tail cut `tau`, each modulus must exceed `max(1, floor(sigma * tau))`; the facade uses `tau = 12`.

## Statistical diagnostics

The `stats` module provides:

- `gaussian_stats`, which centers canonical modular samples and computes their mean, population standard deviation, and cumulative magnitude counts;
- `theoretical_cumulative_probs`, which evaluates the matching truncated discrete Gaussian cumulative probabilities.

These functions are intended for tests and validation tools rather than sampling hot paths. Their rustdoc records the exact floating-point and modulus limits.

## High-precision feature

The optional `high_precision` feature exposes `PreciseCDTSampler` and `SignedPreciseCDTSampler`, which use 256-bit CDT thresholds and support larger tables than the portable CDT backend. The facade types do not select these backends automatically.

## Testing and benchmarks

```text
cargo test -p primus_distr
cargo bench -p primus_distr --bench gen_sampler
cargo bench -p primus_distr --bench sample_gaussian
cargo bench -p primus_distr --bench sample_secret_key
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
