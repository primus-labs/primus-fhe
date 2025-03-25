use algebra::modulus::PowOf2Modulus;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fhe_cmp::{Encryptor, FheCompare, KeyGen, LVL2PARAM_128_BITS_PARAMETERS};
use rand::{distributions::Uniform, Rng};

type M = u64;
const PLAIN_MODULUS_BITS: u32 = 5; //support 1-33bit

pub fn criterion_benchmark(c: &mut Criterion) {
    // set random generator
    let mut rng = rand::thread_rng();

    // set parameter
    let params = *LVL2PARAM_128_BITS_PARAMETERS;
    let modulus = <PowOf2Modulus<M>>::new_with_mask(params.lwe_cipher_modulus_minus_one());
    let distr_msb = Uniform::new_inclusive(0, (1u64 << PLAIN_MODULUS_BITS) - 1);
    let distr_cmp = Uniform::new_inclusive(0, (1u64 << PLAIN_MODULUS_BITS - 1) - 1);

    // generate keys
    let sk = KeyGen::generate_secret_key(params, &mut rng);
    println!("Secret Key Generation done!\n");

    let enc = Encryptor::new(&sk);
    let cmp = FheCompare::new(&sk, &mut rng);
    println!("Evaluation Key Generation done!\n");

    let m0: M = rng.sample(distr_msb);
    let m1: M = rng.sample(distr_cmp);
    let m2: M = rng.sample(distr_cmp);

    let c0 = enc.encrypt(m0, modulus, &mut rng, PLAIN_MODULUS_BITS);
    let c1 = enc.encrypt(m1, modulus, &mut rng, PLAIN_MODULUS_BITS);
    let c2 = enc.encrypt(m2, modulus, &mut rng, PLAIN_MODULUS_BITS);

    c.bench_function("msb", |b| {
        b.iter(|| cmp.hommsb::<M>(black_box(&c0), black_box(PLAIN_MODULUS_BITS)))
    });

    c.bench_function("greater_than", |b| {
        b.iter(|| {
            cmp.greater_than::<M>(
                black_box(&c1),
                black_box(&c2),
                black_box(PLAIN_MODULUS_BITS),
            )
        })
    });

    c.bench_function("greater_than_equal", |b| {
        b.iter(|| {
            cmp.greater_than_equal::<M>(
                black_box(&c1),
                black_box(&c2),
                black_box(PLAIN_MODULUS_BITS),
            )
        })
    });

    c.bench_function("equal", |b| {
        b.iter(|| {
            cmp.equal::<M>(
                black_box(&c1),
                black_box(&c2),
                black_box(PLAIN_MODULUS_BITS),
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
