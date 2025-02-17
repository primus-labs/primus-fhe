use algebra::ntt::NumberTheoryTransform;
use algebra::polynomial::FieldPolynomial;
use algebra::{Field, NttField, U32FieldEval, U64FieldEval};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{distributions::Uniform, prelude::*};

type ValueT = u32;

const LOG_N: u32 = 10;
const N: usize = 1 << LOG_N;

type F32 = U32FieldEval<132120577>;
type F64 = U64FieldEval<1125899906826241>;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = thread_rng();

    let table32 = F32::generate_ntt_table(LOG_N).unwrap();

    let distr = Uniform::new_inclusive(0, F32::MINUS_ONE);

    let poly: Vec<ValueT> = distr.sample_iter(&mut rng).take(N).collect();
    let mut poly = <FieldPolynomial<F32>>::new(poly);

    let degree: usize = rng.gen_range(0..N);
    let coeff = distr.sample(&mut rng);

    c.bench_function(&format!("field 32 ntt {}", N), |b| {
        b.iter(|| {
            table32.transform_slice(poly.as_mut_slice());
        })
    });

    c.bench_function(&format!("field 32 intt {}", N), |b| {
        b.iter(|| {
            table32.inverse_transform_slice(poly.as_mut_slice());
        })
    });

    c.bench_function(&format!("field 32 monomial ntt {}", N), |b| {
        b.iter(|| {
            table32.transform_monomial(coeff, degree, poly.as_mut_slice());
        })
    });

    let table64 = F64::generate_ntt_table(LOG_N + 1).unwrap();

    let distr = Uniform::new_inclusive(0, F64::MINUS_ONE);

    let poly: Vec<_> = distr.sample_iter(&mut rng).take(N << 1).collect();
    let mut poly = <FieldPolynomial<F64>>::new(poly);

    let degree: usize = rng.gen_range(0..(N << 1));
    let coeff = distr.sample(&mut rng);

    c.bench_function(&format!("field 64 ntt {}", N << 1), |b| {
        b.iter(|| {
            table64.transform_slice(poly.as_mut_slice());
        })
    });

    c.bench_function(&format!("field 64 intt {}", N << 1), |b| {
        b.iter(|| {
            table64.inverse_transform_slice(poly.as_mut_slice());
        })
    });

    c.bench_function(&format!("field 64 monomial ntt {}", N << 1), |b| {
        b.iter(|| {
            table64.transform_monomial(coeff, degree, poly.as_mut_slice());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
