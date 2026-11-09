use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_lattice::GlweDimension;
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{
    GadgetSize, GlweSize,
    ggsw::Ggsw,
    glwe::{Glwe, NttGlwe},
    workspace::{NttGlweExternalProductWorkspace, NttGlweTernaryCmuxWorkspace},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_shape::PolyLength;

fn ntt<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Criterion,
    q: T,
    log_b: u32,
    log_n: u32,
    levels: usize,
    dimension: usize,
) {
    let modulus = BarrettModulus::new(q);
    let table = Table::new(PolyLength::new(1usize << log_n), modulus).unwrap();
    let exponent = table.poly_length().get() / 3;
    let basis = ApproxSignedBasis::new(
        Some(q),
        DecompositionBaseLog::new(log_b),
        Some(DecompositionLevelCount::new(levels)),
    );
    let size = GadgetSize::new(
        GlweSize::new(GlweDimension::new(dimension), table.poly_length()),
        DecompositionLevelCount::new(levels),
    );
    let glwe_len = size.glwe_size().glwe_len();
    let input = Glwe::new(
        (0..glwe_len)
            .map(|i| T::as_from(i as u64 * 0x9e37_79b9 + 1) % q)
            .collect::<Vec<_>>(),
    );
    let key = Ggsw::new(
        (0..size.ggsw_len())
            .map(|i| T::as_from(i as u64 * 65_537 + 7) % q)
            .collect::<Vec<_>>(),
    )
    .into_ntt_form(&table);
    let mut output = Glwe::new(vec![T::ZERO; glwe_len]);
    let mut ntt_output = NttGlwe::new(vec![T::ZERO; glwe_len]);
    let mut workspace = NttGlweExternalProductWorkspace::new(size);
    let negative_key = Ggsw::new(
        (0..size.ggsw_len())
            .map(|i| T::as_from(i as u64 * 1_000_003 + 13) % q)
            .collect::<Vec<_>>(),
    )
    .into_ntt_form(&table);
    let mut intermediate = Glwe::new(vec![T::ZERO; glwe_len]);
    let mut ternary_workspace = NttGlweTernaryCmuxWorkspace::new(size);

    let mut group = c.benchmark_group(format!(
        "glwe/ntt/u{}/q{q}/n{}/k{dimension}/logb{log_b}/l{levels}",
        T::BITS,
        table.poly_length().get()
    ));
    group.throughput(Throughput::Elements(glwe_len as u64));
    group.bench_function("external_product_coeff", |b| {
        b.iter(|| {
            black_box(&key).external_product_to(
                black_box(&input),
                black_box(&mut output),
                black_box(&basis),
                black_box(modulus),
                black_box(&table),
                black_box(&mut workspace),
            )
        });
    });
    group.bench_function("external_product_ntt", |b| {
        b.iter(|| {
            black_box(&key).external_product_ntt_to(
                black_box(&input),
                black_box(&mut ntt_output),
                black_box(&basis),
                black_box(modulus),
                black_box(&table),
                black_box(&mut workspace),
            )
        });
    });
    group.bench_function(format!("cmux_monomial_e{exponent}"), |b| {
        b.iter(|| {
            black_box(&key).cmux_monomial_to(
                black_box(&input),
                black_box(exponent),
                black_box(&mut output),
                black_box(&basis),
                black_box(modulus),
                black_box(&table),
                black_box(&mut workspace),
            )
        });
    });
    // Same controls, input, exponent, basis, and coefficient-domain endpoint.
    // One iteration is one ternary step; key generation and scratch allocation
    // stay outside timing. These dense controls measure arithmetic, not noise.
    group.bench_function("ternary_two_cmux", |b| {
        b.iter(|| {
            black_box(&key).cmux_monomial_to(
                black_box(&input),
                black_box(exponent),
                black_box(&mut intermediate),
                black_box(&basis),
                black_box(modulus),
                black_box(&table),
                black_box(&mut workspace),
            );
            black_box(&negative_key).cmux_monomial_to(
                black_box(&intermediate),
                black_box(2 * table.poly_length().get() - exponent),
                black_box(&mut output),
                black_box(&basis),
                black_box(modulus),
                black_box(&table),
                black_box(&mut workspace),
            );
        });
    });
    group.bench_function("ternary_fused", |b| {
        b.iter(|| {
            black_box(&key).cmux_ternary_monomial_to(
                black_box(&negative_key),
                black_box(&input),
                black_box(exponent),
                black_box(&mut output),
                black_box(&basis),
                black_box(modulus),
                black_box(&table),
                black_box(&mut ternary_workspace),
            )
        });
    });
    group.finish();
}

// Match the common PBS decomposition and specialized transform tables.
fn benchmarks(c: &mut Criterion) {
    for log_n in [10, 11] {
        ntt::<u32, U32NttTable>(c, 132_120_577, 5, log_n, 5, 1);
        ntt::<u64, U64NttTable>(c, 1_125_899_906_826_241, 23, log_n, 1, 1);
    }
    ntt::<u32, U32NttTable>(c, 132_120_577, 8, 10, 3, 2);
}
criterion_group! { name = benches; config = Criterion::default().sample_size(20).warm_up_time(std::time::Duration::from_secs(1)).measurement_time(std::time::Duration::from_secs(5)); targets = benchmarks }
criterion_main!(benches);
