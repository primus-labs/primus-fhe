use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_lattice::GlweDimension;
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_lattice::{
    GadgetSize, GlweSize,
    ggsw::{FourierGgswOwned, Ggsw},
    glwe::Glwe,
    workspace::{FourierGlweExternalProductWorkspace, FourierGlweTernaryCmuxWorkspace},
};
use primus_shape::PolyLength;

fn fourier<T: TorusFftValue>(
    c: &mut Criterion,
    backend: &str,
    table: impl FftTable,
    log_b: u32,
    levels: usize,
    dimension: usize,
) {
    let mut fft = FftEngine::new(&table);
    let exponent = fft.poly_length().get() / 3;
    let basis = ApproxSignedBasis::<T>::new(
        None,
        DecompositionBaseLog::new(log_b),
        Some(DecompositionLevelCount::new(levels)),
    );
    let size = GadgetSize::new(
        GlweSize::new(GlweDimension::new(dimension), fft.poly_length()),
        DecompositionLevelCount::new(levels),
    );
    let glwe_len = size.glwe_size().glwe_len();
    // Deterministic coefficient data gives both FFT backends the same workload
    // in their own evaluation order and normalized torus representation.
    let input = Glwe::new(
        (0..glwe_len)
            .map(|i| {
                T::as_from(
                    (i as u64)
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                        .wrapping_add(1),
                )
            })
            .collect::<Vec<_>>(),
    );
    let coeff_key = Ggsw::new(
        (0..size.ggsw_len())
            .map(|i| {
                T::as_from(
                    (i as u64)
                        .wrapping_mul(0xd1b5_4a32_d192_ed03)
                        .wrapping_add(7),
                )
            })
            .collect::<Vec<_>>(),
    );
    let mut key = FourierGgswOwned::zero(size.fourier_ggsw_len());
    coeff_key.write_fourier_form(&mut key, &mut fft);
    let mut output = Glwe::new(vec![T::ZERO; glwe_len]);
    let mut workspace = FourierGlweExternalProductWorkspace::new(size);
    let negative_coeff_key = Ggsw::new(
        (0..size.ggsw_len())
            .map(|i| {
                T::as_from(
                    (i as u64)
                        .wrapping_mul(0xa24b_aed4_963e_e407)
                        .wrapping_add(13),
                )
            })
            .collect::<Vec<_>>(),
    );
    let mut negative_key = FourierGgswOwned::zero(size.fourier_ggsw_len());
    negative_coeff_key.write_fourier_form(&mut negative_key, &mut fft);
    let mut intermediate = Glwe::new(vec![T::ZERO; glwe_len]);
    let mut ternary_workspace = FourierGlweTernaryCmuxWorkspace::new(size);

    let mut group = c.benchmark_group(format!(
        "glwe/fourier/{backend}/u{}/native/n{}/k{dimension}/logb{log_b}/l{levels}",
        T::BITS,
        fft.poly_length().get()
    ));
    group.throughput(Throughput::Elements(glwe_len as u64));
    group.bench_function("external_product_coeff", |b| {
        b.iter(|| {
            black_box(&key).external_product_to(
                black_box(&input),
                black_box(&mut output),
                black_box(&basis),
                black_box(&mut fft),
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
                black_box(&mut fft),
                black_box(&mut workspace),
            )
        });
    });
    // Same two controls and coefficient-domain endpoint. Setup and allocation
    // are outside timing; each iteration evaluates one ternary step.
    group.bench_function("ternary_two_cmux", |b| {
        b.iter(|| {
            black_box(&key).cmux_monomial_to(
                black_box(&input),
                black_box(exponent),
                black_box(&mut intermediate),
                black_box(&basis),
                black_box(&mut fft),
                black_box(&mut workspace),
            );
            black_box(&negative_key).cmux_monomial_to(
                black_box(&intermediate),
                black_box(2 * table.poly_length().get() - exponent),
                black_box(&mut output),
                black_box(&basis),
                black_box(&mut fft),
                black_box(&mut workspace),
            );
        })
    });
    group.bench_function("ternary_fused", |b| {
        b.iter(|| {
            black_box(&key).cmux_ternary_monomial_to(
                black_box(&negative_key),
                black_box(&input),
                black_box(exponent),
                black_box(&mut output),
                black_box(&basis),
                black_box(&mut fft),
                black_box(&mut ternary_workspace),
            );
        })
    });
    group.finish();
}

fn benchmarks(c: &mut Criterion) {
    for log_n in [10u32, 11] {
        let poly_length = PolyLength::new(1usize << log_n);
        fourier::<u32>(c, "rustfft", RustFftTable::new(poly_length), 8, 3, 1);
        fourier::<u64>(c, "rustfft", RustFftTable::new(poly_length), 23, 1, 1);
        fourier::<u32>(c, "tfhe", TfheFftTable::new(poly_length), 8, 3, 1);
        fourier::<u64>(c, "tfhe", TfheFftTable::new(poly_length), 23, 1, 1);
    }
    fourier::<u64>(c, "tfhe", TfheFftTable::new(PolyLength::new(1024)), 8, 3, 2);
}
criterion_group! { name = benches; config = Criterion::default().sample_size(20).warm_up_time(std::time::Duration::from_secs(1)).measurement_time(std::time::Duration::from_secs(5)); targets = benchmarks }
criterion_main!(benches);
