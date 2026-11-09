use primus_shape::PolyLength;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};

fn bench_forward<T: TorusFftValue, Table: FftTable>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group(name);
    for log_n in [9u32, 10, 11, 12] {
        let fft = Table::new(PolyLength::new(1usize << log_n));
        let mut engine = FftEngine::new(&fft);
        let input = (0..fft.poly_length().get())
            .map(|i| T::as_from((i as u64).wrapping_mul(0x9e3779b97f4a7c15)))
            .collect::<Vec<_>>();
        let mut output = vec![Complex64::default(); fft.fourier_length()];
        group.bench_with_input(
            BenchmarkId::from_parameter(fft.poly_length().get()),
            &log_n,
            |b, _| {
                b.iter(|| engine.forward_as_torus(black_box(&input), black_box(&mut output)));
            },
        );
    }
    group.finish();
}

fn bench_inverse<T: TorusFftValue, Table: FftTable>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group(name);
    for log_n in [9u32, 10, 11, 12] {
        let fft = Table::new(PolyLength::new(1usize << log_n));
        let mut engine = FftEngine::new(&fft);
        let input = (0..fft.poly_length().get())
            .map(|i| T::as_from((i as u64).wrapping_mul(0x9e3779b97f4a7c15)))
            .collect::<Vec<_>>();
        let mut fourier = vec![Complex64::default(); fft.fourier_length()];
        let mut output = vec![T::ZERO; fft.poly_length().get()];
        engine.forward_as_torus(&input, &mut fourier);
        group.bench_with_input(
            BenchmarkId::from_parameter(fft.poly_length().get()),
            &log_n,
            |b, _| {
                b.iter(|| engine.backward_as_torus(black_box(&fourier), black_box(&mut output)));
            },
        );
    }
    group.finish();
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
    bench_forward::<u32, RustFftTable>(c, "rustfft_forward_torus_u32");
    bench_forward::<u64, RustFftTable>(c, "rustfft_forward_torus");
    bench_inverse::<u32, RustFftTable>(c, "rustfft_backward_torus_u32");
    bench_inverse::<u64, RustFftTable>(c, "rustfft_backward_torus");
    bench_forward::<u32, TfheFftTable>(c, "tfhe_fft_forward_torus_u32");
    bench_forward::<u64, TfheFftTable>(c, "tfhe_fft_forward_torus");
    bench_inverse::<u32, TfheFftTable>(c, "tfhe_fft_backward_torus_u32");
    bench_inverse::<u64, TfheFftTable>(c, "tfhe_fft_backward_torus");
}

criterion_group! { name = benches; config = Criterion::default().sample_size(20).warm_up_time(std::time::Duration::from_secs(1)).measurement_time(std::time::Duration::from_secs(5)); targets = fft }
criterion_main!(benches);
