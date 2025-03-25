use algebra::modulus::BarrettModulus;
use algebra::ntt::{Concrete64Table, NttTable, NumberTheoryTransform, TableWithShoupRoot};
use algebra::U64FieldEval;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{distributions::Uniform, prelude::*};

type ValueT = u64;

const LOG_N: u32 = 11;
const N: usize = 1 << LOG_N;
const MODULUS: ValueT = 1125899906826241;

pub type F = U64FieldEval<MODULUS>;

pub fn criterion_benchmark(c: &mut Criterion) {
    let modulus = <BarrettModulus<ValueT>>::new(MODULUS);
    let table = <TableWithShoupRoot<ValueT>>::new(modulus, LOG_N).unwrap();
    let concrete_table = <Concrete64Table<F>>::new(modulus, LOG_N).unwrap();

    let mut rng = thread_rng();

    let distr = Uniform::new(0, MODULUS);

    let mut poly: Vec<ValueT> = distr.sample_iter(&mut rng).take(N).collect();
    let degree: usize = rng.gen_range(0..N);
    let coeff = distr.sample(&mut rng);

    c.bench_function(&format!("ntt {}", N), |b| {
        b.iter(|| {
            table.transform_slice(poly.as_mut_slice());
        })
    });

    c.bench_function(&format!("intt {}", N), |b| {
        b.iter(|| {
            table.inverse_transform_slice(poly.as_mut_slice());
        })
    });

    c.bench_function(&format!("concrete ntt {}", N), |b| {
        b.iter(|| {
            concrete_table.transform_slice(poly.as_mut_slice());
        })
    });

    c.bench_function(&format!(" concreteintt {}", N), |b| {
        b.iter(|| {
            concrete_table.inverse_transform_slice(poly.as_mut_slice());
        })
    });

    c.bench_function(&format!("monomial ntt {}", N), |b| {
        b.iter(|| {
            table.transform_monomial(coeff, degree, poly.as_mut_slice());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
