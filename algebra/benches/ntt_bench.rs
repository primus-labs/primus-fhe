use algebra::{transformation::AbstractNTT, Basis, NTTField, Polynomial, Random};
use algebra_derive::{Field, Prime, Random, Ring, NTT};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{prelude::*, thread_rng};

#[derive(Ring, Field, Random, Prime, NTT)]
#[modulus = 132120577]
pub struct Fp(u32);

pub fn criterion_benchmark(c: &mut Criterion) {
    let log_n = 10;
    let n = 1 << log_n;

    Fp::init_ntt_table(&[log_n]).unwrap();

    let mut rng = thread_rng();

    let fp_dis = Fp::standard_distribution();

    let mut data: Vec<Fp> = fp_dis.sample_iter(&mut rng).take(n).collect();

    let ntt_table = Fp::get_ntt_table(log_n).unwrap();

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

    let basis = <Basis<Fp>>::new(3);
    let a = <Polynomial<Fp>>::random_with_dis(n, &mut rng, fp_dis);

    let mut group = c.benchmark_group("Polynomial decompose");

    group.bench_function("polynomial decompose1", |b| {
        b.iter(|| {
            a.decompose1(basis);
        })
    });

    group.bench_function("polynomial decompose2", |b| {
        b.iter(|| {
            a.decompose2(basis);
        })
    });

    group.bench_function("polynomial decompose3", |b| {
        b.iter(|| {
            a.decompose3(basis);
        })
    });

    group.bench_function("polynomial decompose4", |b| {
        b.iter(|| {
            a.decompose4(basis);
        })
    });

    group.bench_function("polynomial decompose5", |b| {
        b.iter(|| {
            a.decompose(basis);
        })
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
