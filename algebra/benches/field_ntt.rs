use algebra::ntt::{NttTable, NumberTheoryTransform};
use algebra::{ntt::FbsTable, polynomial::FieldPolynomial};
use algebra::{Field, U32FieldEval};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{distributions::Uniform, prelude::*};

type ValueT = u32;

const LOG_N: u32 = 10;
const N: usize = 1 << LOG_N;

type Fp = U32FieldEval<132120577>;

pub fn criterion_benchmark(c: &mut Criterion) {
    let table = <FbsTable<Fp>>::new(Fp::MODULUS, LOG_N).unwrap();

    let mut rng = thread_rng();

    let distr = Uniform::new_inclusive(0, Fp::MINUS_ONE);

    let poly: Vec<ValueT> = distr.sample_iter(&mut rng).take(N).collect();
    let mut poly = <FieldPolynomial<Fp>>::new(poly);

    let degree: usize = rng.gen_range(0..N);
    let coeff = distr.sample(&mut rng);

    c.bench_function(&format!("field ntt {}", N), |b| {
        b.iter(|| {
            table.transform_slice(poly.as_mut_slice());
        })
    });

    c.bench_function(&format!("field intt {}", N), |b| {
        b.iter(|| {
            table.inverse_transform_slice(poly.as_mut_slice());
        })
    });

    c.bench_function(&format!("field monomial ntt {}", N), |b| {
        b.iter(|| {
            table.transform_monomial(coeff, degree, poly.as_mut_slice());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
