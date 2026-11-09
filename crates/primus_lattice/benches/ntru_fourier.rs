use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_lattice::{
    ngsw::{FourierNgswOwned, Ngsw},
    ntru::{FourierNtruOwned, Ntru},
    workspace::FourierNtruExternalProductWorkspace,
};
use primus_shape::PolyLength;

fn fourier<T: TorusFftValue>(
    c: &mut Criterion,
    backend: &str,
    table: impl FftTable,
    log_b: u32,
    levels: usize,
) {
    let mut fft = FftEngine::new(&table);
    let exponent = fft.poly_length().get() / 3;
    let basis = ApproxSignedBasis::<T>::new(
        None,
        DecompositionBaseLog::new(log_b),
        Some(DecompositionLevelCount::new(levels)),
    );
    let poly_length = fft.poly_length().get();
    // Deterministic coefficient data gives both FFT backends the same workload
    // in their own evaluation order and normalized torus representation.
    let input = Ntru::new(
        (0..poly_length)
            .map(|i| {
                T::as_from(
                    (i as u64)
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                        .wrapping_add(1),
                )
            })
            .collect::<Vec<_>>(),
    );
    let coeff_key = Ngsw::new(
        (0..levels * poly_length)
            .map(|i| {
                T::as_from(
                    (i as u64)
                        .wrapping_mul(0xd1b5_4a32_d192_ed03)
                        .wrapping_add(7),
                )
            })
            .collect::<Vec<_>>(),
    );
    let mut key = FourierNgswOwned::zero(levels * fft.fourier_length());
    coeff_key.write_fourier_form(&mut key, &mut fft);
    let mut output = Ntru::new(vec![T::ZERO; poly_length]);
    let mut fourier_output = FourierNtruOwned::zero(poly_length / 2);
    let mut workspace = FourierNtruExternalProductWorkspace::new(PolyLength::new(poly_length));

    let mut group = c.benchmark_group(format!(
        "ntru/fourier/{backend}/u{}/native/n{}/logb{log_b}/l{levels}",
        T::BITS,
        fft.poly_length().get()
    ));
    group.throughput(Throughput::Elements(poly_length as u64));
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
    group.bench_function("external_product_fourier", |b| {
        b.iter(|| {
            black_box(&key).external_product_fourier_to(
                black_box(&input),
                black_box(&mut fourier_output),
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
    group.finish();
}

fn benchmarks(c: &mut Criterion) {
    for log_n in [10u32, 11] {
        let poly_length = PolyLength::new(1usize << log_n);
        fourier::<u32>(c, "rustfft", RustFftTable::new(poly_length), 9, 3);
        fourier::<u64>(c, "rustfft", RustFftTable::new(poly_length), 9, 7);
        fourier::<u32>(c, "tfhe", TfheFftTable::new(poly_length), 9, 3);
        fourier::<u64>(c, "tfhe", TfheFftTable::new(poly_length), 9, 7);
    }
}
criterion_group! { name = benches; config = Criterion::default().sample_size(20).warm_up_time(std::time::Duration::from_secs(1)).measurement_time(std::time::Duration::from_secs(5)); targets = benchmarks }
criterion_main!(benches);
