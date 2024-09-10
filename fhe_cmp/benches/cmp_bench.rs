use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fhe_cmp::{
    compare::{Encryptor, HomeCmpScheme},
    parameters::DEFAULT_PARAMETERS,
};
use fhe_core::{RLWEBlindRotationKey, SecretKeyPack};
use rand::prelude::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    // set random generator
    let mut rng = rand::thread_rng();
    // set parameter
    let param = *DEFAULT_PARAMETERS;
    // generate keys
    let sk = SecretKeyPack::new(param);
    println!("Secret Key Generation done!\n");

    let sampler = param.ring_noise_distribution();
    let rotationkey = HomeCmpScheme::new(RLWEBlindRotationKey::generate(&sk), param);
    let enc_elements = Encryptor::new(param, sk.ntt_ring_secret_key().clone(), sampler);
    println!("Evaluation Key Generation done!\n");

    let x = rng.gen();
    let y = rng.gen();
    let (value1, value2) = enc_elements.encrypt(x, y, &mut rng);

    c.bench_function("less comparison", |b| {
        b.iter(|| rotationkey.lt_arbhcmp(&value1, &value2))
    });
    c.bench_function("equality comparison", |b| {
        b.iter(|| rotationkey.eq_arbhcmp(black_box(&value1), black_box(&value2)))
    });
    c.bench_function("greater comparison", |b| {
        b.iter(|| rotationkey.gt_arbhcmp(black_box(&value1), black_box(&value2)))
    });
}
criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
