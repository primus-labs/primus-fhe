use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fhe_cmp::{
    compare::{Encryptor, HomomorphicCmpScheme},
    parameters::DEFAULT_PARAMETERS,
};
use fhe_core::SecretKeyPack;
use rand::prelude::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    // set random generator
    let mut rng = rand::thread_rng();
    // set parameter
    let param = *DEFAULT_PARAMETERS;
    // generate keys
    let skp = SecretKeyPack::new(param);
    println!("Secret Key Generation done!\n");

    let rotation_key = HomomorphicCmpScheme::new(&skp);
    let encryptor = Encryptor::new(&skp);
    println!("Evaluation Key Generation done!\n");

    let n = param.ring_dimension();
    let n2 = n.checked_mul(n).unwrap();
    let n3 = n2.checked_mul(n).unwrap();

    let x = rng.gen_range(0..n);
    let y = rng.gen_range(0..n);
    let value1 = encryptor.rlwe_encrypt(x, &mut rng);
    let value2 = encryptor.rgsw_encrypt(y, &mut rng);

    c.bench_function("less comparison: 1 chunks", |b| {
        b.iter(|| rotation_key.lt_arbhcmp(black_box(&value1), black_box(&value2)))
    });
    c.bench_function("equality comparison: 1 chunks", |b| {
        b.iter(|| rotation_key.eq_arbhcmp(black_box(&value1), black_box(&value2)))
    });
    c.bench_function("greater comparison: 1 chunks", |b| {
        b.iter(|| rotation_key.gt_arbhcmp(black_box(&value1), black_box(&value2)))
    });

    let x = rng.gen_range(n2..n3);
    let y = rng.gen_range(n2..n3);
    let value1 = encryptor.rlwe_encrypt(x, &mut rng);
    let value2 = encryptor.rgsw_encrypt(y, &mut rng);

    c.bench_function("less comparison: 3 chunks", |b| {
        b.iter(|| rotation_key.lt_arbhcmp(black_box(&value1), black_box(&value2)))
    });
    c.bench_function("equality comparison: 3 chunks", |b| {
        b.iter(|| rotation_key.eq_arbhcmp(black_box(&value1), black_box(&value2)))
    });
    c.bench_function("greater comparison: 3 chunks", |b| {
        b.iter(|| rotation_key.gt_arbhcmp(black_box(&value1), black_box(&value2)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);