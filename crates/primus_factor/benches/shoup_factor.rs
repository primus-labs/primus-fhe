use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_factor::{FactorSliceOps, ShoupFactor};
use rand::distr::{Distribution, Uniform};

type ValueT = u64;

fn bench_shoup_factor(c: &mut Criterion) {
    let mut rng = rand::rng();

    let distr = Uniform::new(0, ValueT::MAX >> 1).unwrap();
    let modulus = distr.sample(&mut rng);
    let distr_value = Uniform::new(0, modulus).unwrap();

    let factor = ShoupFactor::new(distr_value.sample(&mut rng), modulus);

    for n in [1024, 2048, 4096] {
        let data: Vec<ValueT> = (0..n).map(|_| distr_value.sample(&mut rng)).collect();
        let mut result = vec![0; n];

        c.bench_function(&format!("factor_mul_slice_to/n={n}"), |b| {
            b.iter(|| {
                factor.factor_mul_slice_to(black_box(&data), black_box(&mut result), modulus);
            })
        });

        c.bench_function(&format!("add_factor_mul_slice_assign/n={n}"), |b| {
            b.iter(|| {
                factor.add_factor_mul_slice_assign(
                    black_box(&mut result),
                    black_box(&data),
                    modulus,
                );
            })
        });
    }
}

criterion_group!(benches, bench_shoup_factor);
criterion_main!(benches);
