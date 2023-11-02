use algebra::{
    field::{prime_fields::Fp32, NTTField},
    polynomial::{NTTPolynomial, Polynomial},
};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{distributions::Uniform, prelude::*, thread_rng};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut r = thread_rng();

    const P: u32 = 0x7e00001;
    type Fp = Fp32<P>;

    let log_n = 10;
    let n = 1 << log_n;
    let ntt_table = Fp::generate_ntt_table(log_n).unwrap();

    let dist = Uniform::new(0, P);
    let data: Vec<_> = dist.sample_iter(&mut r).take(n).map(Fp::from).collect();

    let poly = Polynomial::<Fp>::new(data.clone());

    c.bench_function(&format!("ntt {}", n), |b| {
        b.iter(|| {
            ntt_table.transform(&poly);
        })
    });

    let poly = NTTPolynomial::<Fp>::new(data);

    c.bench_function(&format!("intt {}", n), |b| {
        b.iter(|| {
            ntt_table.inverse_transform(&poly);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
