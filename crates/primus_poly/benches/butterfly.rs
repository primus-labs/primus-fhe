use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
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

    for &(label, moduli) in cases {
        let moduli_count = moduli.len();
        let total_len = moduli_count * poly_length;

        // Generate random data per modulus chunk.
        let mut lhs_base = vec![0u64; total_len];
        let mut rhs_base = vec![0u64; total_len];
        let mut w_base = vec![ShoupFactor::default(); total_len];

        izip!(
            lhs_base.chunks_exact_mut(poly_length),
            rhs_base.chunks_exact_mut(poly_length),
            w_base.chunks_exact_mut(poly_length),
            moduli
        )
        .for_each(|(l, r, w, &m)| {
            let distr = Uniform::new(0, m).unwrap();
            l.iter_mut()
                .zip(distr.sample_iter(&mut rng))
                .for_each(|(a, b)| *a = b);
            r.iter_mut()
                .zip(distr.sample_iter(&mut rng))
                .for_each(|(a, b)| *a = b);
            w.iter_mut()
                .zip(distr.sample_iter(&mut rng))
                .for_each(|(a, b)| a.set(b, m));
        });

        let mut lhs = DcrtPolynomial(lhs_base);
        let rhs = DcrtPolynomial(rhs_base);
        let mut result = DcrtPolynomial(vec![0; total_len]);

        c.bench_function(
            &format!("butterfly_mul_factor/{label}/n={poly_length}"),
            |b| {
                b.iter(|| {
                    lhs.butterfly_mul_factor_to(
                        black_box(&rhs),
                        black_box(&w_base),
                        black_box(&mut result),
                        black_box(poly_length),
                        black_box(moduli),
                    );
                    black_box(lhs.as_slice());
                    black_box(result.as_slice());
                });
            },
        );
    }
}

criterion_group!(benches, bench_butterfly);
criterion_main!(benches);
