use boolean_fhe::{EvaluationKey, SecretKeyPack, DEFAULT_TERNARY_128_BITS_PARAMERTERS};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;

pub fn criterion_benchmark(c: &mut Criterion) {
    // set random generator
    let mut rng = rand::thread_rng();

    // set parameter
    let default_parameters = DEFAULT_TERNARY_128_BITS_PARAMERTERS.clone();

    // generate keys
    let skp = SecretKeyPack::new(default_parameters);
    println!("Secret Key Generation done!\n");

    let evk = EvaluationKey::new(&skp);
    println!("Evaluation Key Generation done!\n");

    let m0 = rng.gen();
    let c0 = skp.encrypt(m0);

    let m1 = rng.gen();
    let c1 = skp.encrypt(m1);

    let m2 = rng.gen();
    let c2 = skp.encrypt(m2);

    c.bench_function("not", |b| b.iter(|| evk.not(black_box(&c0))));

    c.bench_function("and", |b| {
        b.iter(|| evk.and(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("nand", |b| {
        b.iter(|| evk.nand(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("or", |b| b.iter(|| evk.or(black_box(&c0), black_box(&c1))));

    c.bench_function("nor", |b| {
        b.iter(|| evk.nor(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("xor", |b| {
        b.iter(|| evk.xor(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("xnor", |b| {
        b.iter(|| evk.xnor(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("majority", |b| {
        b.iter(|| evk.majority(black_box(&c0), black_box(&c1), black_box(&c2)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
