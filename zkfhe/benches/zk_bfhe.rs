use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;
use zkfhe::bfhe::{Encryptor, Evaluator, KeyGen, DEFAULT_TERNARY_128_BITS_PARAMERTERS};

pub fn criterion_benchmark(c: &mut Criterion) {
    // set random generator
    let mut rng = rand::thread_rng();

    // set parameter
    let default_parameters = *DEFAULT_TERNARY_128_BITS_PARAMERTERS;

    // generate keys
    let sk = KeyGen::generate_secret_key(default_parameters);
    println!("Secret Key Generation done!\n");

    let encryptor = Encryptor::new(sk.clone());
    let evaluator = Evaluator::new(sk);
    println!("Evaluation Key Generation done!\n");

    let m0 = rng.gen();
    let c0 = encryptor.encrypt(m0);

    let m1 = rng.gen();
    let c1 = encryptor.encrypt(m1);

    let m2 = rng.gen();
    let c2 = encryptor.encrypt(m2);

    c.bench_function("rlwe not", |b| b.iter(|| evaluator.not(black_box(&c0))));

    c.bench_function("rlwe and", |b| {
        b.iter(|| evaluator.and(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("rlwe nand", |b| {
        b.iter(|| evaluator.nand(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("rlwe or", |b| {
        b.iter(|| evaluator.or(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("rlwe nor", |b| {
        b.iter(|| evaluator.nor(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("rlwe xor", |b| {
        b.iter(|| evaluator.xor(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("rlwe xnor", |b| {
        b.iter(|| evaluator.xnor(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("rlwe majority", |b| {
        b.iter(|| evaluator.majority(black_box(&c0), black_box(&c1), black_box(&c2)))
    });

    c.bench_function("rlwe mux", |b| {
        b.iter(|| evaluator.mux(black_box(&c0), black_box(&c1), black_box(&c2)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
