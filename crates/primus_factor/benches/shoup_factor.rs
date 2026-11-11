//! cargo bench -p primus_factor --bench shoup_factor
//! cargo +nightly bench -p primus_factor --bench shoup_factor --features simd

use std::{hint::black_box, time::Duration};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_factor::{FactorSliceOps, ShoupFactor};
use primus_integer::FheUint;

fn slices<T: FheUint + TryFrom<u64> + Into<u64>>(c: &mut Criterion, word: &str, modulus: T) {
    // Match the modulus baseline's multiplier. Construct it outside the timed loop.
    let factor = ShoupFactor::new(T::as_from(17u64), modulus);
    let q = modulus.into();
    for n in [1024, 1025, 4096] {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut values = || {
            (0..n)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    T::try_from(state % q)
                        .ok()
                        .expect("value fits the benchmark word")
                })
                .collect::<Vec<T>>()
        };
        let data = values();
        let rhs = values();
        let mut output = data.clone();
        let mut group = c.benchmark_group(format!("factor/shoup/{word}/q{q}/n{n}"));
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function("mul_to", |b| {
            b.iter(|| {
                black_box(factor).factor_mul_slice_to(
                    black_box(&data),
                    black_box(&mut output),
                    black_box(modulus),
                )
            })
        });
        group.bench_function("mul_assign", |b| {
            b.iter(|| {
                black_box(factor)
                    .factor_mul_slice_assign(black_box(&mut output), black_box(modulus))
            })
        });
        group.bench_function("add_mul_assign", |b| {
            b.iter(|| {
                black_box(factor).add_factor_mul_slice_assign(
                    black_box(&mut output),
                    black_box(&rhs),
                    black_box(modulus),
                )
            })
        });
        group.bench_function("sub_mul_assign", |b| {
            b.iter(|| {
                black_box(factor).sub_factor_mul_slice_assign(
                    black_box(&mut output),
                    black_box(&rhs),
                    black_box(modulus),
                )
            })
        });
        group.finish();
    }
}

fn benchmarks(c: &mut Criterion) {
    slices(c, "u32", 132_120_577u32);
    // Cover both the usual NTT modulus and the upper end of Shoup's range.
    // Factor arithmetic does not require a prime modulus.
    for q in [1_125_899_906_826_241u64, (1 << 63) - 1] {
        slices(c, "u64", q);
    }
}
criterion_group! {
    name = benches;
    // Keep the full 36-case matrix practical for local runs.
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1));
    targets = benchmarks
}
criterion_main!(benches);
