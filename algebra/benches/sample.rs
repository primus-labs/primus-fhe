use algebra::{
    utils::{sample_binary_field_vec, sample_cbd_field_vec, sample_ternary_field_vec, Prg},
    Polynomial,
};
use algebra_derive::Field;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

#[derive(Field)]
#[modulus = 132120577]
pub struct Fp(u32);

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut prg = Prg::new();
    let mut rng = ChaCha12Rng::from_entropy();

    let n = 1024;

    c.bench_function(&format!("aes random bits {}", n), |b| {
        b.iter(|| {
            sample_binary_field_vec::<Fp, _>(n, &mut prg);
        })
    });

    c.bench_function(&format!("chacha12 random bits {}", n), |b| {
        b.iter(|| {
            sample_binary_field_vec::<Fp, _>(n, &mut rng);
        })
    });

    c.bench_function(&format!("aes random ternary {}", n), |b| {
        b.iter(|| {
            sample_ternary_field_vec::<Fp, _>(n, &mut prg);
        })
    });

    c.bench_function(&format!("chacha12 random ternary {}", n), |b| {
        b.iter(|| {
            sample_ternary_field_vec::<Fp, _>(n, &mut rng);
        })
    });

    c.bench_function(&format!("aes random cbd {}", n), |b| {
        b.iter(|| {
            sample_cbd_field_vec::<Fp, _>(n, &mut prg);
        })
    });

    c.bench_function(&format!("chacha12 random cbd {}", n), |b| {
        b.iter(|| {
            sample_cbd_field_vec::<Fp, _>(n, &mut rng);
        })
    });

    c.bench_function(&format!("aes poly random {}", n), |b| {
        b.iter(|| {
            Polynomial::<Fp>::random(n, &mut prg);
        })
    });

    c.bench_function(&format!("chacha12 poly random {}", n), |b| {
        b.iter(|| {
            Polynomial::<Fp>::random(n, &mut rng);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
