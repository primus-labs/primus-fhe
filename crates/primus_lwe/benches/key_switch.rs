// cargo bench -p primus_lwe --bench key_switch
// Performance fixtures, not evaluated security parameters.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_lattice::LweDimension;
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_lattice::lwe::{LweIter, LweIterMut};
use primus_lwe::{
    LweEncryptionParameters, LweKeySwitchingKey, LweKeySwitchingParameters, LweSecretKey,
    LweSecretKeyRef, SecretKeyDistr,
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;
use rand::distr::Distribution;
use rand::{SeedableRng, rngs::StdRng};

fn bench_domain<M: RingContext<u32>>(c: &mut Criterion, name: &str, modulus: M) {
    for log_basis in [2, 4] {
        let mut rng = StdRng::seed_from_u64(0xdec0_005e);
        let params = LweEncryptionParameters::new(
            LweDimension::new(800),
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let secret = LweSecretKey::generate(&params, &mut rng);
        let basis = ApproxSignedBasis::new(
            modulus.explicit_value(),
            DecompositionBaseLog::new(log_basis),
            None,
        );
        let levels = basis.level_count().get();
        let key_parameters = LweKeySwitchingParameters::new(params, basis);
        let key = LweKeySwitchingKey::generate(
            LweSecretKeyRef::Encoded(&[1; 1024]),
            &secret,
            &key_parameters,
            &mut rng,
        );
        let input: Vec<u32> = key_parameters
            .output()
            .cipher_modulus_uniform_distr()
            .sample_iter(&mut rng)
            .take(1025 * 16)
            .collect();
        for count in [1, 16] {
            let input = &input[..1025 * count];
            let mut output = vec![0; 801 * count];
            let mut group = c.benchmark_group(format!(
                "lwe_key_switch/u32/{name}/n1024_to800/logB{log_basis}_L{levels}/count{count}"
            ));
            group.throughput(Throughput::Elements(count as u64));
            group.bench_function("single_loop", |b| {
                b.iter(|| {
                    for (input, mut output) in LweIter::new(black_box(input), 1025)
                        .zip(LweIterMut::new(black_box(&mut output), 801))
                    {
                        black_box(&key).key_switch_to(&input, &mut output, black_box(modulus));
                    }
                })
            });
            // The one-element batch delegates to the single kernel. Compare
            // blocked and independent processing only where entries are reused.
            if count > 1 {
                group.bench_function("batch_to", |b| {
                    b.iter(|| {
                        black_box(&key).key_switch_batch_to(
                            black_box(input),
                            black_box(&mut output),
                            black_box(modulus),
                        );
                    })
                });
            }
            group.finish();
        }
    }
}
fn key_switch(c: &mut Criterion) {
    bench_domain(c, "native", NativeModulus::new());
    bench_domain(c, "explicit", BarrettModulus::new(132_120_577));
}
const CIPHERTEXT_MODULUS: u32 = 132_120_577;
const OUTPUT_DIMENSION: usize = 800;
const LOG_BASIS: u32 = 2;
const LEVEL_COUNT: usize = 13;

fn bench_generation(c: &mut Criterion) {
    let modulus = BarrettModulus::new(CIPHERTEXT_MODULUS);
    let output_parameters = LweEncryptionParameters::new(
        LweDimension::new(OUTPUT_DIMENSION),
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let basis = ApproxSignedBasis::new(
        Some(CIPHERTEXT_MODULUS),
        DecompositionBaseLog::new(LOG_BASIS),
        Some(DecompositionLevelCount::new(LEVEL_COUNT)),
    );
    let mut rng = StdRng::seed_from_u64(0xdec0_005e);
    let output_secret_key = LweSecretKey::generate(&output_parameters, &mut rng);
    let key_parameters = LweKeySwitchingParameters::new(output_parameters, basis);
    let mut group = c.benchmark_group("lwe_key_switch_generation/u32/explicit");
    group.sample_size(10);

    // One representative size tracks generation; applying the key above
    // already separates modulus and decomposition-kernel costs.
    let input_secret_key = [1u32; 1024];
    group.bench_function("generate_n1024_to_n800", |bencher| {
        bencher.iter(|| {
            LweKeySwitchingKey::generate(
                LweSecretKeyRef::Encoded(black_box(&input_secret_key)),
                &output_secret_key,
                &key_parameters,
                &mut rng,
            )
        });
    });
    group.finish();
}

criterion_group!(benches, key_switch, bench_generation);
criterion_main!(benches);
