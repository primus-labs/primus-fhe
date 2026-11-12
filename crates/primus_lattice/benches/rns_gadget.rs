//! Run with `cargo bench -p primus_lattice --bench rns_gadget --features rns`.
//! GLev and GGSW products over one ordinary ordered RNS base.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::{DecompositionBaseLog, big_integer::BigUintApproxSignedBasis};
use primus_lattice::{
    GlweDimension, GlweSize, RnsGadgetSize, RnsGlweSize,
    ggsw::CrtGgsw,
    glwe::{CrtGlwe, DcrtGlwe},
    workspace::DcrtGlevMulWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::BigUintPolynomial;
use primus_rns::RNSBase;
use primus_shape::PolyLength;

const MODULI: [u64; 4] = [
    1_125_899_906_826_241,
    1_125_899_906_629_633,
    1_125_899_906_031_617,
    1_125_899_904_679_937,
];

// Canonical [component][modulus][coefficient] data. Independent residues
// exercise full-width decomposition across the ordered base.
fn coefficients(len: usize, n: usize, moduli: &[u64], seed: u64) -> Vec<u64> {
    let mut state = seed;
    (0..len)
        .map(|i| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % moduli[i / n % moduli.len()]
        })
        .collect()
}

fn benchmarks(c: &mut Criterion) {
    let poly_length = PolyLength::new(1024);
    let n = poly_length.get();
    // Vary rank, limb count or decomposition depth individually.
    for (dimension, count, log_b) in [(1, 2, 20), (2, 2, 20), (1, 4, 20), (1, 2, 10)] {
        let qs = &MODULI[..count];
        let moduli: Vec<_> = qs.iter().copied().map(BarrettModulus::new).collect();
        let base = RNSBase::new(&moduli).unwrap();
        let table = U64DcrtTable::new(poly_length, &moduli).unwrap();
        let basis = BigUintApproxSignedBasis::new(
            base.moduli_product(),
            DecompositionBaseLog::new(log_b),
            None,
        );
        let levels = basis.level_count();
        let glwe_size = RnsGlweSize::new(
            GlweSize::new(GlweDimension::new(dimension), poly_length),
            count,
        );
        let size = RnsGadgetSize::new(glwe_size, levels);
        let glwe_len = glwe_size.rns_glwe_len();
        let key = CrtGgsw::new(coefficients(size.rns_ggsw_len(), n, qs, 17)).into_ntt_form(&table);
        let input = CrtGlwe::new(coefficients(glwe_len, n, qs, 29));
        let mut output = DcrtGlwe::<Vec<u64>>::zero(glwe_len);
        let mut workspace = DcrtGlevMulWorkspace::new(size, &base);

        // The first GGSW row and input component have the GLev product layout.
        let glev = key.iter_dcrt_glev(size.rns_glev_len()).next().unwrap();
        let crt_input = input
            .iter_crt_poly(glwe_size.rns_poly_len())
            .next()
            .unwrap();
        let mut big_input = BigUintPolynomial::new(vec![0; n * base.big_uint_value_len()]);
        let mut compose_scratch = vec![0; base.moduli_count()];
        base.compose_big_uint_values_to(
            crt_input.as_ref(),
            big_input.as_mut_slice(),
            n,
            &mut compose_scratch,
        );
        glev.mul_crt_polynomial_to(
            &crt_input,
            &mut output,
            &basis,
            &table,
            &base,
            &mut workspace,
        );
        let expected = output.clone();
        glev.mul_big_uint_polynomial_to(
            &big_input,
            &mut output,
            &basis,
            &table,
            &base,
            &mut workspace,
        );
        assert_eq!(output.as_ref(), expected.as_ref());

        let label = format!(
            "u64/n{n}/k{dimension}/m{count}/logb{log_b}/l{}",
            levels.get()
        );
        let mut group = c.benchmark_group(format!("rns/glev/{label}"));
        group.throughput(Throughput::Elements(glwe_len as u64));
        group.bench_function("crt_to", |b| {
            b.iter(|| {
                black_box(&glev).mul_crt_polynomial_to(
                    black_box(&crt_input),
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
                black_box(&glev).mul_big_uint_polynomial_to(
                    black_box(&big_input),
                    black_box(&mut output),
                    black_box(&basis),
                    black_box(&table),
                    black_box(&base),
                    black_box(&mut workspace),
                )
            })
        });
        // Repeated accumulation stays canonical, with no timed output reset.
        group.bench_function("crt_add_assign", |b| {
            b.iter(|| {
                black_box(&mut output).add_dcrt_glev_mul_crt_polynomial_assign(
                    black_box(&glev),
                    black_box(&crt_input),
                    black_box(&basis),
                    black_box(&table),
                    black_box(&base),
                    black_box(&mut workspace),
                )
            })
        });
        group.finish();

        let mut group = c.benchmark_group(format!("rns/ggsw/{label}"));
        group.throughput(Throughput::Elements(glwe_len as u64));
        group.bench_function("crt_to_dcrt", |b| {
            b.iter(|| {
                black_box(&key).external_product_to(
                    black_box(&input),
                    black_box(&mut output),
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
