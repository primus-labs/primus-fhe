use boolean_fhe::{EvaluationKey, SecretKeyPack, DEFAULT_100_BITS_PARAMERTERS};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;

pub fn criterion_benchmark(c: &mut Criterion) {
    // set random generator
    let mut rng = rand::thread_rng();

    // set parameter
    let default_parameters = DEFAULT_100_BITS_PARAMERTERS.clone();

    // generate keys
    let skp = SecretKeyPack::new(default_parameters);
    println!("Secret Key Generation done!\n");

    let evk = EvaluationKey::new(&skp);
    println!("Evaluation Key Generation done!\n");

    let m0 = rng.gen();
    let c0 = skp.encrypt(m0);

    let m1 = rng.gen();
    let c1 = skp.encrypt(m1);

    c.bench_function("nand", |b| {
        b.iter(|| evk.nand(black_box(&c0), black_box(&c1)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
