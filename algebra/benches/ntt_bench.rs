use algebra::field::NTTField;
use algebra::field::{BarrettConfig, Fp32};
use algebra::polynomial::{NTTPolynomial, Polynomial};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{distributions::Uniform, prelude::*, thread_rng};

pub fn criterion_benchmark(c: &mut Criterion) {
    const P: u32 = Fp32::BARRETT_MODULUS.value();

    let log_n = 10;
    let n = 1 << log_n;

    Fp32::init_ntt_table(&[log_n]).unwrap();

    let dist = Uniform::new(0, P);
    let mut r = thread_rng();
    let data: Vec<_> = dist.sample_iter(&mut r).take(n).map(Fp32::from).collect();

    let poly = Polynomial::<Fp32>::new(data.clone());

    // let ntt_table = Fp32::get_ntt_table(log_n).unwrap();

    c.bench_function(&format!("ntt {}", n), |b| {
        b.iter(|| {
            // ntt_table.transform(&poly);
            poly.clone().to_ntt_polynomial();
        })
    });

    let poly = NTTPolynomial::<Fp32>::new(data);

    c.bench_function(&format!("intt {}", n), |b| {
        b.iter(|| {
            // ntt_table.inverse_transform(&poly);
            poly.clone().to_native_polynomial();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
