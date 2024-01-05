use criterion::{black_box, criterion_group, criterion_main, Criterion};

use algebra::derive::{Field, Prime, Random, Ring, NTT};
use boolean_fhe::{EvaluationKey, Parameters, SecretKeyPack, SecretKeyType};
use rand::Rng;

#[derive(Ring, Random)]
#[modulus = 1024]
pub struct RR(u32);

#[derive(Ring, Field, Random, Prime, NTT)]
#[modulus = 1073692673]
pub struct FF(u32);

pub fn criterion_benchmark(c: &mut Criterion) {
    // set random generator
    // use rand::SeedableRng;
    // let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(11);
    let mut rng = rand::thread_rng();

    // set parameter
    let params = <Parameters<RR, FF>>::new(512, 1024, SecretKeyType::Ternary, 6, 5, 3.2, 3.2);

    // generate keys
    let skp = SecretKeyPack::new(params, &mut rng);
    println!("Secret Key Generation done!\n");

    let evk = EvaluationKey::new(&skp, &mut rng);
    println!("Evaluation Key Generation done!\n");

    let m0 = rng.gen();
    let c0 = skp.encrypt(m0, &mut rng);

    let m1 = rng.gen();
    let c1 = skp.encrypt(m1, &mut rng);

    c.bench_function("nand", |b| {
        b.iter(|| evk.nand(black_box(c0.clone()), black_box(&c1)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
