// cargo bench -p primus_lwe --bench public_key
// cargo +nightly bench -p primus_lwe --bench public_key --features simd
// These are performance fixtures, not evaluated security parameters.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_encoding::PlaintextEmbedding;
use primus_integer::{AsFrom, FheUint};
use primus_lattice::LweDimension;
use primus_lattice::lwe::LweIterMut;
use primus_lwe::{LweParameters, LwePublicKey, LweSecretKey, LweSecretKeyRef, SecretKeyDistr};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

// Generation fixes n; batch encryption below varies dimensions and counts.
fn bench_generation<T: FheUint>(c: &mut Criterion, name: &str, modulus: impl RingContext<T>) {
    let dimension = 1024;
    let params = LweParameters::new(
        LweDimension::new(dimension),
        T::as_from(4u32),
        modulus,
        SecretKeyDistr::UniformTernary,
        3.2,
    );
    let mut state = 0x8356_125f_334d_aaaa_u64;
    let signed: Vec<T::SignedInteger> = (0..dimension)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            T::SignedInteger::as_from((state % 3) as i64 - 1)
        })
        .collect();
    let encoded: Vec<T> = signed.iter().map(|&s| modulus.encode_signed(s)).collect();
    let mut group = c.benchmark_group(format!("lwe_public_key/{name}/n{dimension}/generate"));
    // Includes output allocation and all n zero encryptions; encoding is setup.
    // Both views share the timed body and start from the same RNG seed.
    for (name, secret) in [
        ("encoded", LweSecretKeyRef::Encoded(&encoded)),
        ("signed", LweSecretKeyRef::Signed(&signed)),
    ] {
        group.bench_function(name, |b| {
            let mut rng = StdRng::seed_from_u64(0x1_ee15);
            b.iter(|| {
                let params = black_box(&params);
                LwePublicKey::generate(
                    black_box(secret),
                    params.dimension(),
                    params.cipher_modulus(),
                    params.cipher_modulus_uniform_distr(),
                    params.noise_distribution(),
                    &mut rng,
                )
            });
        });
    }
    group.finish();
}

fn bench_batch_domain<M: RingContext<u32>>(c: &mut Criterion, name: &str, modulus: M) {
    // Cover both Gaussian backends; CDT also tracks matrix-size scaling and
    // a non-power-of-two dimension without duplicating those cases for Ziggurat.
    for (sigma, dimension, count) in [
        (3.2, 512, 1),
        (3.2, 512, 64),
        (3.2, 805, 64),
        (3.2, 1024, 64),
        (30.0, 512, 1),
        (30.0, 512, 64),
    ] {
        let mut rng = StdRng::seed_from_u64(0x1_ee25);
        let params = LweParameters::new(
            LweDimension::new(dimension),
            4,
            modulus,
            SecretKeyDistr::UniformBinary,
            sigma,
        );
        let secret = LweSecretKey::generate(params.encryption_parameters(), &mut rng);
        let public = LwePublicKey::generate(
            secret.as_view(),
            params.dimension(),
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            &mut rng,
        );
        let messages = vec![1u32; count];
        let mut output = vec![0u32; (dimension + 1) * count];
        let mut group = c.benchmark_group(format!(
            "lwe_public_key/u32/{name}/sigma{sigma}/n{dimension}/count{count}"
        ));
        group.throughput(Throughput::Elements(count as u64));
        // One iteration encrypts exactly count independent messages; both cases
        // reuse identical output/key storage and include fresh random sampling.
        group.bench_function("single_loop", |b| {
            b.iter(|| {
                for (&message, mut ciphertext) in black_box(&messages)
                    .iter()
                    .zip(LweIterMut::new(black_box(&mut output), dimension + 1))
                {
                    black_box(&public).encrypt_message_to(
                        message,
                        &mut ciphertext,
                        black_box(&params),
                        PlaintextEmbedding::Unsigned,
                        &mut rng,
                    );
                }
            })
        });
        // Count one records single-message latency. Larger counts compare
        // row reuse against the same number of independent encryptions.
        if count > 1 {
            group.bench_function("batch_to", |b| {
                b.iter(|| {
                    black_box(&public).encrypt_message_batch_to(
                        black_box(&messages),
                        black_box(&mut output),
                        black_box(&params),
                        PlaintextEmbedding::Unsigned,
                        &mut rng,
                    );
                })
            });
        }
        group.finish();
    }
}

fn public_key(c: &mut Criterion) {
    bench_generation(c, "u32/native", NativeModulus::<u32>::new());
    bench_generation(c, "u64/native", NativeModulus::<u64>::new());
    bench_generation(c, "u32/barrett", BarrettModulus::new(132_120_577u32));
    bench_generation(
        c,
        "u64/barrett",
        BarrettModulus::new(1_152_921_504_606_846_977u64),
    );
    bench_batch_domain(c, "native", NativeModulus::new());
    bench_batch_domain(c, "explicit", BarrettModulus::new(132_120_577));
}

criterion_group!(benches, public_key);
criterion_main!(benches);
