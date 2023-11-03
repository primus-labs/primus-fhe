use algebra::field::prime_fields::{BarrettConfig, Fp32};
use algebra::field::NTTField;
use algebra::polynomial::{NTTPolynomial, Polynomial};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{distributions::Uniform, prelude::*, thread_rng};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut r = thread_rng();

    const P: u32 = Fp32::BARRETT_MODULUS.value();

    let log_n = 10;
    let n = 1 << log_n;
    let ntt_table = Fp32::generate_ntt_table(log_n).unwrap();

    let dist = Uniform::new(0, P);
    let data: Vec<_> = dist.sample_iter(&mut r).take(n).map(Fp32::from).collect();

    let poly = Polynomial::<Fp32>::new(data.clone());

    c.bench_function(&format!("ntt {}", n), |b| {
        b.iter(|| {
            ntt_table.transform(&poly);
        })
    });

    let poly = NTTPolynomial::<Fp32>::new(data);

    c.bench_function(&format!("intt {}", n), |b| {
        b.iter(|| {
            ntt_table.inverse_transform(&poly);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
