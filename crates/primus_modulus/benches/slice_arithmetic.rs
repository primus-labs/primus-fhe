//! Canonical slice operations used by ciphertext arithmetic.
//! cargo bench -p primus_modulus --bench slice_arithmetic
//! cargo +nightly bench -p primus_modulus --bench slice_arithmetic --features simd

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;
use std::hint::black_box;

fn arithmetic<T: FheUint + TryFrom<u64>, M: RingContext<T>>(
    c: &mut Criterion,
    name: &str,
    modulus: M,
    q: u64,
    bench_add_to: bool,
) {
    for n in [1024, 1025, 4096] {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut data = || {
            (0..n)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    T::try_from(state % q)
                        .ok()
                        .expect("value fits the benchmark word")
                })
                .collect::<Vec<_>>()
        };
        let lhs = data();
        let rhs = data();
        let mut output = lhs.clone();
        let scalar = T::try_from(17u64).ok().unwrap();
        let mut group = c.benchmark_group(format!("slice/arithmetic/{name}/n{n}"));
        group.throughput(Throughput::Elements(n as u64));
        // Native add_to is already covered by slice_moduli.
        if bench_add_to {
            group.bench_function("add_to", |b| {
                b.iter(|| {
                    black_box(modulus).reduce_add_slice_to(
                        black_box(&lhs),
                        black_box(&rhs),
                        black_box(&mut output),
                    )
                })
            });
        }
        group.bench_function("add_assign", |b| {
            b.iter(|| {
                black_box(modulus).reduce_add_slice_assign(black_box(&mut output), black_box(&rhs))
            })
        });
        group.bench_function("sub_to", |b| {
            b.iter(|| {
                black_box(modulus).reduce_sub_slice_to(
                    black_box(&lhs),
                    black_box(&rhs),
                    black_box(&mut output),
                )
            })
        });
        group.bench_function("sub_assign", |b| {
            b.iter(|| {
                black_box(modulus).reduce_sub_slice_assign(black_box(&mut output), black_box(&rhs))
            })
        });
        group.bench_function("neg_to", |b| {
            b.iter(|| {
                black_box(modulus).reduce_neg_slice_to(black_box(&lhs), black_box(&mut output))
            })
        });
        group.bench_function("neg_assign", |b| {
            b.iter(|| black_box(modulus).reduce_neg_slice_assign(black_box(&mut output)))
        });
        group.bench_function("mul_scalar_to", |b| {
            b.iter(|| {
                black_box(modulus).reduce_mul_scalar_slice_to(
                    black_box(&lhs),
                    black_box(scalar),
                    black_box(&mut output),
                )
            })
        });
        group.bench_function("mul_scalar_assign", |b| {
            b.iter(|| {
                black_box(modulus)
                    .reduce_mul_scalar_slice_assign(black_box(&mut output), black_box(scalar))
            })
        });
        group.bench_function("add_mul_scalar_assign", |b| {
            b.iter(|| {
                black_box(modulus).reduce_add_mul_scalar_slice_assign(
                    black_box(&mut output),
                    black_box(&rhs),
                    black_box(scalar),
                )
            })
        });
        group.finish();
    }
}

fn benchmarks(c: &mut Criterion) {
    arithmetic(
        c,
        "native/u32",
        NativeModulus::<u32>::new(),
        1u64 << 32,
        false,
    );
    arithmetic(
        c,
        "native/u64",
        NativeModulus::<u64>::new(),
        u64::MAX,
        false,
    );
    arithmetic(
        c,
        "barrett/u32/q132120577",
        BarrettModulus::new(132_120_577u32),
        132_120_577,
        true,
    );
    arithmetic(
        c,
        "barrett/u64/q1125899906826241",
        BarrettModulus::new(1_125_899_906_826_241u64),
        1_125_899_906_826_241,
        true,
    );
}
criterion_group!(benches, benchmarks);
criterion_main!(benches);
