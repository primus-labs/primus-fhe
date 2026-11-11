use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_integer::FheUint;
use primus_lattice::{glwe::Glwe, lwe::Lwe, ntru::Ntru};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;

// Extraction acts on coefficients: Fourier and NTT do not need duplicate cases.
fn extraction<T: FheUint + From<u32>, M: RingContext<T>>(
    c: &mut Criterion,
    domain: &str,
    modulus: M,
) {
    let n = 1024;
    let data: Vec<T> = (0..3 * n).map(|i| T::from((i * 31 + 7) as u32)).collect();
    let glwe = Glwe::new(data.as_slice());
    let ntru = Ntru::new(&data[..n]);
    let mut group = c.benchmark_group(format!("extraction/{domain}/n{n}"));
    let mut output: Lwe<Vec<T>> = Lwe::zero(n);
    let sample_index = n / 3;
    group.throughput(Throughput::Elements((n + 1) as u64));
    group.bench_function(format!("ntru/full/a{n}/index{sample_index}"), |b| {
        b.iter(|| {
            ntru.extract_lwe_at_to(
                black_box(sample_index),
                black_box(&mut output),
                black_box(modulus),
            )
        });
    });

    // Compare the compact zero/nonzero positions and full/short masks at one
    // common position. The input GLWE remains full-sized in each case.
    let compact_len = n + n / 2;
    for (active, index) in [
        (compact_len, 0),
        (compact_len, sample_index),
        (2 * n, sample_index),
    ] {
        let mut output: Lwe<Vec<T>> = Lwe::zero(active);
        group.throughput(Throughput::Elements((active + 1) as u64));
        group.bench_function(format!("glwe/k2/compact/a{active}/index{index}"), |b| {
            b.iter(|| {
                glwe.extract_compact_lwe_at_to(
                    black_box(index),
                    black_box(&mut output),
                    black_box(n),
                    black_box(modulus),
                )
            });
        });
    }

    // Non-polynomial-aligned input also measures the padding/clearing path.
    let lwe = Lwe::new(&data[..compact_len + 1]);
    let mut output = Glwe::new(vec![T::ZERO; 3 * n]);
    group.throughput(Throughput::Elements((3 * n) as u64));
    group.bench_function("glwe/k2/inverse_compact", |b| {
        b.iter(|| {
            lwe.inverse_extract_glwe_to(black_box(&mut output), black_box(n), black_box(modulus))
        });
    });
    group.finish();
}

fn benchmarks(c: &mut Criterion) {
    extraction(c, "native/u64", NativeModulus::<u64>::new());
    extraction(c, "q132120577/u32", BarrettModulus::new(132_120_577u32));
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
