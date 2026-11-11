//! DCRT factor butterfly on modulus-major data.
//! cargo bench -p primus_poly --bench butterfly
//! cargo +nightly bench -p primus_poly --bench butterfly --features simd

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use itertools::izip;
use primus_factor::ShoupFactor;
use primus_poly::DcrtPolynomial;
use rand::{
    SeedableRng,
    distr::{Distribution, Uniform},
    rngs::StdRng,
};

type ValueT = u64;

fn bench_butterfly(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0xB07E_2F1A_0000_0001);

    let cases: &[(&str, &[ValueT])] = &[
        ("2mod", &[1125899906826241, 1125899906629633]),
        ("3mod", &[137438822401, 137438814209, 137438773249]),
    ];

    let poly_length = 4096;
    let mut group = c.benchmark_group("butterfly_mul_factor");

    for &(label, moduli) in cases {
        let moduli_count = moduli.len();
        let total_len = moduli_count * poly_length;

        let [mut lhs, mut rhs, mut result] =
            std::array::from_fn(|_| DcrtPolynomial::<Vec<ValueT>>::zero(total_len));
        let mut factors = vec![ShoupFactor::default(); total_len];

        // Fill both operands and their factors in modulus order before timing.
        for (lhs, rhs, factors, &q) in izip!(
            lhs.iter_each_modulus_mut(poly_length),
            rhs.iter_each_modulus_mut(poly_length),
            factors.chunks_exact_mut(poly_length),
            moduli
        ) {
            let mut samples = Uniform::new(0, q).unwrap().sample_iter(&mut rng);
            for (value, sample) in lhs.iter_mut().chain(rhs).zip(&mut samples) {
                *value = sample;
            }
            for (factor, sample) in factors.iter_mut().zip(samples) {
                factor.set(sample, q);
            }
        }

        group.throughput(Throughput::Elements(total_len as u64));
        group.bench_function(format!("{label}/n={poly_length}"), |b| {
            b.iter(|| {
                lhs.butterfly_mul_factor_to(
                    black_box(&rhs),
                    black_box(&factors),
                    black_box(&mut result),
                    black_box(poly_length),
                    black_box(moduli),
                );
                black_box(lhs.as_slice());
                black_box(result.as_slice());
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_butterfly);
criterion_main!(benches);
