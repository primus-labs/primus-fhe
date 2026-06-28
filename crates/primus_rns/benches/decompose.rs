use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_factor::{FactorBase, ShoupFactor};
use primus_modulus::BarrettModulus;
use primus_reduce::Modulus;
use primus_rns::RNSBase;
use rand::distr::{Distribution, Uniform};

type ValueT = u64;

/// Production moduli:
///   p ≤ 128: 2 moduli of ~50 bits
///   p ≥ 256: 3 moduli of ~37-38 bits
fn production_rns_base(moduli: &[ValueT]) -> RNSBase<ValueT, BarrettModulus<ValueT>> {
    let moduli: Vec<_> = moduli.iter().map(|&m| BarrettModulus::new(m)).collect();
    RNSBase::new(&moduli).unwrap()
}

fn bench_decompose(c: &mut Criterion) {
    let mut rng = rand::rng();

    let cases: &[(&str, &[ValueT], ValueT)] = &[
        // (label, moduli, small_modulus = basis_value = 2^log_basis)
        (
            "2mod/logB=13",
            &[1125899906826241, 1125899906629633],
            1 << 13,
        ), // 8192
        (
            "2mod/logB=18",
            &[1125899906826241, 1125899906629633],
            1 << 18,
        ), // 262144
        (
            "2mod/logB=23",
            &[1125899906826241, 1125899906629633],
            1 << 23,
        ), // 8388608
        (
            "3mod/logB=13",
            &[137438822401, 137438814209, 137438773249],
            1 << 13,
        ),
        (
            "3mod/logB=15",
            &[137438822401, 137438814209, 137438773249],
            1 << 15,
        ), // 32768
        (
            "3mod/logB=17",
            &[137438822401, 137438814209, 137438773249],
            1 << 17,
        ), // 131072
    ];

    let poly_length = 4096; // production value from parameters.rs

    for &(label, moduli, small_modulus) in cases {
        let moduli_count = moduli.len();
        let value_count = poly_length;
        let rns_base = production_rns_base(moduli);

        // Generate small values in [0, small_modulus)
        let small_values: Vec<ValueT> = {
            let distr = Uniform::new(0, small_modulus).unwrap();
            (0..value_count).map(|_| distr.sample(&mut rng)).collect()
        };
        let mut multi_residues = vec![0u64; moduli_count * value_count];

        // ---- wrapping_decompose_small_values_to ----
        c.bench_function(
            &format!("wrapping_decompose/{label}/n={poly_length}"),
            |b| {
                b.iter(|| {
                    rns_base.wrapping_decompose_small_values_to(
                        black_box(&small_values),
                        black_box(&mut multi_residues),
                        value_count,
                        small_modulus,
                    );
                });
            },
        );

        // ---- add_wrapping_decompose_small_values_scaled ----
        let factors: Vec<ShoupFactor<ValueT>> = rns_base
            .moduli()
            .iter()
            .map(|m| {
                let m_val = unsafe { m.value_unchecked() };
                let distr = Uniform::new(0, m_val).unwrap();
                ShoupFactor::new(distr.sample(&mut rng), m_val)
            })
            .collect();
        let mut acc = vec![0u64; moduli_count * value_count];

        c.bench_function(
            &format!("add_wrapping_decompose_scaled/{label}/n={poly_length}"),
            |b| {
                b.iter(|| {
                    rns_base.add_wrapping_decompose_small_values_scaled(
                        black_box(&small_values),
                        black_box(&mut acc),
                        value_count,
                        small_modulus,
                        black_box(&factors),
                    );
                });
            },
        );
    }
}

criterion_group!(benches, bench_decompose);
criterion_main!(benches);
