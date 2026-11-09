use std::hint::black_box;

#[path = "support/rns.rs"]
mod support;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::{DecompositionBaseLog, big_integer::BigUintApproxSignedBasis};
use primus_lattice::{
    GlweDimension, GlweSize, RnsGadgetSize, RnsGlweSize, glev::CrtGlev, glwe::DcrtGlwe,
    workspace::DcrtGlevMulWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::{BigUintPolynomial, CrtPolynomial};
use primus_rns::RNSBase;
use primus_shape::PolyLength;

fn benchmarks(c: &mut Criterion) {
    for &(log_n, dimension, count, log_b) in support::CASES {
        let n = 1usize << log_n;
        let qs = &support::MODULI[..count];
        let moduli: Vec<_> = qs.iter().copied().map(BarrettModulus::new).collect();
        let base = RNSBase::new(&moduli).unwrap();
        let table = U64DcrtTable::new(PolyLength::new(1usize << log_n), &moduli).unwrap();
        let basis = BigUintApproxSignedBasis::new(
            base.moduli_product(),
            DecompositionBaseLog::new(log_b),
            None,
        );
        let levels = basis.level_count();
        let size = RnsGadgetSize::new(
            RnsGlweSize::new(
                GlweSize::new(GlweDimension::new(dimension), PolyLength::new(n)),
                count,
            ),
            levels,
        );
        let glwe_len = size.rns_glwe_size().rns_glwe_len();
        let key = CrtGlev::new(support::coefficients(size.rns_glev_len(), n, qs, 17))
            .into_ntt_form(&table);
        let input = CrtPolynomial::new(support::coefficients(n * count, n, qs, 29));
        let mut big_input = BigUintPolynomial::new(vec![0; n * base.big_uint_value_len()]);
        let mut workspace = DcrtGlevMulWorkspace::new(size, &base);
        let mut compose_scratch = vec![0; base.moduli_count()];
        base.compose_big_uint_values_to(
            input.as_ref(),
            big_input.as_mut_slice(),
            n,
            &mut compose_scratch,
        );
        let mut output = DcrtGlwe::new(vec![0; glwe_len]);
        // Both entry paths must compute the same product. Check outside timing.
        key.mul_crt_polynomial_to(&input, &mut output, &basis, &table, &base, &mut workspace);
        let expected = output.clone();
        key.mul_big_uint_polynomial_to(
            &big_input,
            &mut output,
            &basis,
            &table,
            &base,
            &mut workspace,
        );
        assert_eq!(output.as_ref(), expected.as_ref());

        let mut group = c.benchmark_group(format!(
            "rns/glev/u64/n{n}/k{dimension}/m{count}/logb{log_b}/l{}",
            levels.get()
        ));
        group.throughput(Throughput::Elements(glwe_len as u64));
        group.bench_function("crt_to", |b| {
            b.iter(|| {
                black_box(&key).mul_crt_polynomial_to(
                    black_box(&input),
                    black_box(&mut output),
                    black_box(&basis),
                    black_box(&table),
                    black_box(&base),
                    black_box(&mut workspace),
                )
            })
        });
        group.bench_function("big_uint_to", |b| {
            b.iter(|| {
                black_box(&key).mul_big_uint_polynomial_to(
                    black_box(&big_input),
                    black_box(&mut output),
                    black_box(&basis),
                    black_box(&table),
                    black_box(&base),
                    black_box(&mut workspace),
                )
            })
        });
        // Repeated modular accumulation stays canonical; reset/copy is not part
        // of the key-switch inner operation and is not inserted into timing.
        group.bench_function("crt_add_assign", |b| {
            b.iter(|| {
                black_box(&mut output).add_dcrt_glev_mul_crt_polynomial_assign(
                    black_box(&key),
                    black_box(&input),
                    black_box(&basis),
                    black_box(&table),
                    black_box(&base),
                    black_box(&mut workspace),
                )
            })
        });
        group.finish();
    }
}
criterion_group!(benches, benchmarks);
criterion_main!(benches);
