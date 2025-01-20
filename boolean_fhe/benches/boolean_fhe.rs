use boolean_fhe::{Encryptor, Evaluator, KeyGen, DEFAULT_128_BITS_PARAMETERS};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{distributions::Uniform, Rng};

type M = u8;

pub fn criterion_benchmark(c: &mut Criterion) {
    // set random generator
    let mut rng = rand::thread_rng();

    // set parameter
    let default_parameters = *DEFAULT_128_BITS_PARAMETERS;

    let distr = Uniform::new_inclusive(0, 1);

    // generate keys
    let sk = KeyGen::generate_secret_key(default_parameters, &mut rng);
    println!("Secret Key Generation done!\n");

    let encryptor = Encryptor::new(&sk);
    let evaluator = Evaluator::new(&sk, &mut rng);
    println!("Evaluation Key Generation done!\n");

    let m0: M = rng.sample(distr);
    let m1: M = rng.sample(distr);
    let m2: M = rng.sample(distr);

    let c0 = encryptor.encrypt(m0, &mut rng);
    let c1 = encryptor.encrypt(m1, &mut rng);
    let c2 = encryptor.encrypt(m2, &mut rng);

    c.bench_function("not", |b| b.iter(|| evaluator.not(black_box(&c0))));

    c.bench_function("nand", |b| {
        b.iter(|| evaluator.nand(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("and", |b| {
        b.iter(|| evaluator.and(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("or", |b| {
        b.iter(|| evaluator.or(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("nor", |b| {
        b.iter(|| evaluator.nor(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("xor", |b| {
        b.iter(|| evaluator.xor(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("xnor", |b| {
        b.iter(|| evaluator.xnor(black_box(&c0), black_box(&c1)))
    });

    c.bench_function("majority", |b| {
        b.iter(|| evaluator.majority(black_box(&c0), black_box(&c1), black_box(&c2)))
    });

    c.bench_function("mux", |b| {
        b.iter(|| evaluator.mux(black_box(&c0), black_box(&c1), black_box(&c2)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
