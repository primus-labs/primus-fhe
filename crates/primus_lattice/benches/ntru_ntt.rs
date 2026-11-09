use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{
    ngsw::Ngsw,
    ntru::{Ntru, NttNtru},
    workspace::NttNtruExternalProductWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable, U64NttTable};
use primus_shape::PolyLength;

fn ntt<T: FheUint, Table: NttTable<ValueT = T>>(
    c: &mut Criterion,
    q: T,
    log_b: u32,
    log_n: u32,
    levels: usize,
) {
    let modulus = BarrettModulus::new(q);
    let table = Table::new(PolyLength::new(1usize << log_n), modulus).unwrap();
    let exponent = table.poly_length().get() / 3;
    let basis = ApproxSignedBasis::new(
        Some(q),
        DecompositionBaseLog::new(log_b),
        Some(DecompositionLevelCount::new(levels)),
    );
    let poly_length = table.poly_length().get();
    let input = Ntru::new(
        (0..poly_length)
            .map(|i| T::as_from(i as u64 * 0x9e37_79b9 + 1) % q)
            .collect::<Vec<_>>(),
    );
    let key = Ngsw::new(
        (0..levels * poly_length)
            .map(|i| T::as_from(i as u64 * 65_537 + 7) % q)
            .collect::<Vec<_>>(),
    )
    .into_ntt_form(&table);
    let mut output = Ntru::new(vec![T::ZERO; poly_length]);
    let mut ntt_output = NttNtru::<Vec<T>>::zero(poly_length);
    let mut workspace = NttNtruExternalProductWorkspace::new(PolyLength::new(poly_length));

    let mut group = c.benchmark_group(format!(
        "ntru/ntt/u{}/q{q}/n{}/logb{log_b}/l{levels}",
        T::BITS,
        table.poly_length().get()
    ));
    group.throughput(Throughput::Elements(poly_length as u64));
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
    group.finish();
}

// Match the common PBS decomposition and specialized transform tables.
fn benchmarks(c: &mut Criterion) {
    for log_n in [10, 11] {
        ntt::<u32, U32NttTable>(c, 132_120_577, 9, log_n, 3);
        ntt::<u64, U64NttTable>(c, 1_125_899_906_826_241, 9, log_n, 5);
    }
}
criterion_group! { name = benches; config = Criterion::default().sample_size(20).warm_up_time(std::time::Duration::from_secs(1)).measurement_time(std::time::Duration::from_secs(5)); targets = benchmarks }
criterion_main!(benches);
