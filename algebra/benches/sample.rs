use algebra::utils::{
    sample_binary_field_vec, sample_cbd_field_vec, sample_ternary_field_vec, Prg,
};
use algebra_derive::Field;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;

#[derive(Field)]
#[modulus = 132120577]
pub struct Fp(u32);

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut prg = Prg::new();
    let mut rng = thread_rng();

    let n = 1024;

    c.bench_function(&format!("aes random bits {}", n), |b| {
        b.iter(|| {
            sample_binary_field_vec::<Fp, _>(n, &mut prg);
        })
    });

    c.bench_function(&format!("thread_rng random bits {}", n), |b| {
        b.iter(|| {
            sample_binary_field_vec::<Fp, _>(n, &mut rng);
        })
    });

    c.bench_function(&format!("aes random ternary {}", n), |b| {
        b.iter(|| {
            sample_ternary_field_vec::<Fp, _>(n, &mut prg);
        })
    });

    c.bench_function(&format!("thread_rng random ternary {}", n), |b| {
        b.iter(|| {
            sample_ternary_field_vec::<Fp, _>(n, &mut rng);
        })
    });

    c.bench_function(&format!("aes random cbd {}", n), |b| {
        b.iter(|| {
            sample_cbd_field_vec::<Fp, _>(n, &mut prg);
        })
    });

    c.bench_function(&format!("thread_rng random cbd {}", n), |b| {
        b.iter(|| {
            sample_cbd_field_vec::<Fp, _>(n, &mut rng);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
