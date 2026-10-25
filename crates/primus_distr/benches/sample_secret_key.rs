// cargo bench -p primus_distr --bench sample_secret_key
// Measures prepared whole-key sampling and shared CRT ephemeral coefficients.
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_distr::{SecretKeyDistr, SecretKeySampler, sample_crt_sparse_ternary_values_to};
use rand::{SeedableRng, rngs::StdRng};

fn signed_sampling(c: &mut Criterion) {
    let mut group = c.benchmark_group("secret_key/signed_i32_to");
    for length in [1024, 16384] {
        let mut output = vec![0i32; length];
        let mut rng = StdRng::seed_from_u64(301);
        for (name, distr) in [
            ("uniform_binary", SecretKeyDistr::UniformBinary),
            ("binary", SecretKeyDistr::binary(0.3)),
            ("sparse_ternary", SecretKeyDistr::SparseTernary),
            ("uniform_ternary", SecretKeyDistr::UniformTernary),
            ("ternary", SecretKeyDistr::ternary(0.2, 0.4)),
            (
                "fixed_binary_sparse",
                SecretKeyDistr::fixed_hamming_weight_binary(length, 64),
            ),
            (
                "fixed_binary_dense",
                SecretKeyDistr::fixed_hamming_weight_binary(length, length / 2),
            ),
            (
                "fixed_ternary",
                SecretKeyDistr::fixed_hamming_weight_ternary(length, 64),
            ),
            (
                "fixed_composition_sparse",
                SecretKeyDistr::fixed_composition_ternary(length, 32, 32),
            ),
            (
                "fixed_composition_dense",
                SecretKeyDistr::fixed_composition_ternary(length, length / 3, length / 3),
            ),
            ("gaussian", SecretKeyDistr::gaussian(3.2)),
            ("gaussian_ziggurat", SecretKeyDistr::gaussian(30.0)),
        ] {
            let sampler = SecretKeySampler::<u32>::new(distr);
            group.throughput(Throughput::Elements(length as u64));
            group.bench_function(BenchmarkId::new(name, length), |b| {
                b.iter(|| {
                    sampler.sample_signed_to(black_box(&mut output), &mut rng);
                    black_box(&output);
                })
            });
        }
    }
    group.finish();
}

fn crt_sampling(c: &mut Criterion) {
    let mut group = c.benchmark_group("secret_key/crt_sparse_ternary_u64_to");
    for length in [1024, 16384] {
        for count in [2, 8] {
            let moduli_minus_one: Vec<u64> =
                (0..count).map(|i| 1_000_000_006 + 2 * i as u64).collect();
            let mut output = vec![0u64; length * count];
            let mut rng = StdRng::seed_from_u64(302);
            group.throughput(Throughput::Elements(output.len() as u64));
            group.bench_function(BenchmarkId::new(format!("moduli_{count}"), length), |b| {
                b.iter(|| {
                    sample_crt_sparse_ternary_values_to(
                        black_box(&mut output),
                        length,
                        &moduli_minus_one,
                        &mut rng,
                    );
                    black_box(&output);
                })
            });
        }
    }
    group.finish();
}

fn encoded_sampling(c: &mut Criterion) {
    let mut group = c.benchmark_group("secret_key/encoded_u32_to");
    for length in [1024, 16384] {
        let mut output = vec![0u32; length];
        for (name, distr) in [
            ("uniform_binary", SecretKeyDistr::UniformBinary),
            ("ternary", SecretKeyDistr::ternary(0.2, 0.4)),
            (
                "fixed_binary_dense",
                SecretKeyDistr::fixed_hamming_weight_binary(length, length / 2),
            ),
            (
                "fixed_composition_dense",
                SecretKeyDistr::fixed_composition_ternary(length, length / 3, length / 3),
            ),
        ] {
            let sampler = SecretKeySampler::<u32>::new(distr);
            let mut rng = StdRng::seed_from_u64(305);
            group.throughput(Throughput::Elements(length as u64));
            group.bench_function(BenchmarkId::new(name, length), |b| {
                b.iter(|| {
                    sampler.sample_encoded_to(black_box(&mut output), 132_120_576u32, &mut rng)
                });
            });
        }
    }
    group.finish();

    let mut group = c.benchmark_group("secret_key/encoded_u64_to");
    for length in [1024, 16384] {
        let mut output = vec![0u64; length];
        for (name, sigma) in [("gaussian", 3.2), ("gaussian_ziggurat", 30.0)] {
            let sampler = SecretKeySampler::<u64>::new(SecretKeyDistr::gaussian(sigma));
            let mut rng = StdRng::seed_from_u64(303);
            group.throughput(Throughput::Elements(length as u64));
            group.bench_function(BenchmarkId::new(name, length), |b| {
                b.iter(|| sampler.sample_encoded_to(black_box(&mut output), u64::MAX, &mut rng));
            });
        }
    }
    group.finish();
}

fn allocating_sampling(c: &mut Criterion) {
    // Includes allocation: this is the owning key-generation path.
    let mut group = c.benchmark_group("secret_key/gaussian_allocating");
    let length = 16384;
    group.throughput(Throughput::Elements(length as u64));
    for (name, sigma) in [("cdt", 3.2), ("ziggurat", 30.0)] {
        let distr = SecretKeyDistr::gaussian(sigma);
        let signed = SecretKeySampler::<u32>::new(distr);
        let encoded = SecretKeySampler::<u64>::new(distr);
        let mut rng = StdRng::seed_from_u64(304);
        group.bench_function(
            BenchmarkId::new(format!("signed_i32_{name}"), length),
            |b| {
                b.iter(|| black_box(signed.sample_signed(length, &mut rng)));
            },
        );
        let mut rng = StdRng::seed_from_u64(304);
        group.bench_function(
            BenchmarkId::new(format!("encoded_u64_{name}"), length),
            |b| {
                b.iter(|| black_box(encoded.sample_encoded(length, u64::MAX, &mut rng)));
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    signed_sampling,
    encoded_sampling,
    allocating_sampling,
    crt_sampling
);
criterion_main!(benches);
