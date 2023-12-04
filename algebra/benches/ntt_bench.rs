use algebra::field::NTTField;
use algebra::transformation::AbstractNTT;
use algebra_derive::{Field, Prime, Random, Ring, NTT};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{distributions::Standard, prelude::*, thread_rng};

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Field, Random, Prime, NTT,
)]
#[modulus = 132120577]
pub struct Fp32(u32);

pub fn criterion_benchmark(c: &mut Criterion) {
    let log_n = 10;
    let n = 1 << log_n;

    Fp32::init_ntt_table(&[log_n]).unwrap();

    let mut r = thread_rng();
    let mut data: Vec<_> = Standard.sample_iter(&mut r).take(n).collect();

    let ntt_table = Fp32::get_ntt_table(log_n).unwrap();

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
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
