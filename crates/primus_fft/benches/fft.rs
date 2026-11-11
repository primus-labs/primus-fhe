//! cargo bench -p primus_fft --bench fft --features rustfft,tfhe-fft

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_shape::PolyLength;

/// Measures both directions with the same table and prepared workspace.
fn bench_torus<T: TorusFftValue, Table: FftTable>(
    c: &mut Criterion,
    backend: &str,
    word_suffix: &str,
    tables: &[Table],
) {
    let mut cases: Vec<_> = tables
        .iter()
        .map(|table| {
            let n = table.poly_length().get();
            let mut engine = FftEngine::new(table);
            let input: Vec<T> = (0..n)
                .map(|i| T::as_from((i as u64).wrapping_mul(0x9e3779b97f4a7c15)))
                .collect();
            let mut spectrum = vec![Complex64::default(); table.fourier_length()];
            // Populate the inverse input even if the forward benchmark is filtered out.
            engine.forward_as_torus(&input, &mut spectrum);
            (engine, input, spectrum, vec![T::ZERO; n])
        })
        .collect();

    let mut group = c.benchmark_group(format!("{backend}_forward_torus{word_suffix}"));
    for (engine, input, spectrum, _) in &mut cases {
        let n = input.len();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| engine.forward_as_torus(black_box(&*input), black_box(&mut *spectrum)));
        });
    }
    group.finish();

    let mut group = c.benchmark_group(format!("{backend}_backward_torus{word_suffix}"));
    for (engine, _, spectrum, output) in &mut cases {
        let n = output.len();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| engine.backward_as_torus(black_box(&*spectrum), black_box(&mut *output)));
        });
    }
    group.finish();
}

fn bench_backend<Table: FftTable>(c: &mut Criterion, name: &str) {
    // Keep a common accumulator size and a larger LUT workset for both words.
    let tables = [1024, 4096].map(|n| Table::new(PolyLength::new(n)));
    bench_torus::<u32, _>(c, name, "_u32", &tables);
    bench_torus::<u64, _>(c, name, "", &tables);
}

fn bench_conversion<T: TorusFftValue>(c: &mut Criterion) {
    let input: Vec<_> = (0..2048).map(|i| (i as f64 - 1024.0) / 17.0).collect();
    let mut output = vec![T::ZERO; input.len()];

    c.bench_function(&format!("u{}_torus_conversion/2048", T::BITS), |b| {
        b.iter(|| {
            for (&input, output) in black_box(&input).iter().zip(black_box(&mut output)) {
                *output = T::from_torus_f64(input);
            }
        })
    });
}

fn fft(c: &mut Criterion) {
    bench_conversion::<u32>(c);
    bench_conversion::<u64>(c);
    bench_backend::<RustFftTable>(c, "rustfft");
    bench_backend::<TfheFftTable>(c, "tfhe_fft");
}

criterion_group!(benches, fft);
criterion_main!(benches);
