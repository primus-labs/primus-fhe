use algebra::{
    transformation::{AbstractNTT, MonomialNTT},
    Basis, FieldUniformSampler, NTTField, Polynomial,
};
use algebra_derive::{DecomposableField, FheField, Field, Prime, NTT};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::prelude::*;

#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
pub struct Fp(u32);

pub fn criterion_benchmark(c: &mut Criterion) {
    let log_n = 10;
    let n = 1 << log_n;

    Fp::init_ntt_table(&[log_n]).unwrap();

    let mut rng = thread_rng();

    let fp_dis = FieldUniformSampler::new();

    let mut data: Vec<Fp> = fp_dis.sample_iter(&mut rng).take(n).collect();

    let ntt_table = Fp::get_ntt_table(log_n).unwrap();

    let uniform = FieldUniformSampler::new();
    let coeff = uniform.sample(&mut rng);
    let degree = rng.gen_range(1..n);

    c.bench_function(&format!("ntt {}", n), |b| {
        b.iter(|| {
            ntt_table.transform_slice(data.as_mut_slice());
        })
    });

    c.bench_function(&format!("intt {}", n), |b| {
        b.iter(|| {
            ntt_table.inverse_transform_slice(data.as_mut_slice());
        })
    });

    c.bench_function(&format!("monomial ntt {}", n), |b| {
        b.iter(|| {
            ntt_table.transform_monomial(coeff, degree, data.as_mut_slice());
        })
    });

    let basis = <Basis<Fp>>::new(3);
    let mut a = <Polynomial<Fp>>::random_with_distribution(n, &mut rng, fp_dis);

    let decompose_len = basis.decompose_len();

    let mut decompose = Vec::new();
    decompose.resize_with(decompose_len, || <Polynomial<Fp>>::zero(n));

    let mut group = c.benchmark_group("Polynomial decompose");

    group.bench_function("polynomial decompose", |b| {
        b.iter_batched(|| a.clone(), |a| a.decompose(basis), BatchSize::SmallInput)
    });

    group.bench_function("polynomial decompose inplace", |b| {
        b.iter(|| {
            a.decompose_inplace(basis, &mut decompose);
        })
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
