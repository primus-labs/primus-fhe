//! Run with `cargo bench -p primus_modulus --bench barrett_slice`.
//!
//! To benchmark the SIMD implementation, run
//! `cargo +nightly bench -p primus_modulus --bench barrett_slice --features simd`.

use core::{hint::black_box, time::Duration};

use criterion::{
    BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main,
    measurement::Measurement,
};
use primus_modulus::{BarrettModulus, UintModulus};
use primus_reduce::prelude::*;
use rand::{
    SeedableRng,
    distr::{Distribution, Uniform, uniform::SampleUniform},
    rngs::StdRng,
};

const RNG_SEED: u64 = 0x6d6f_6475_6c75_735f;
const MODULUS_U32: u32 = 1_073_692_673;
const MODULUS_U64: u64 = 1_125_899_906_826_241;
const POLY_LENGTH: usize = 4_096;
const SCALING_LENGTHS: [usize; 4] = [256, 1_024, POLY_LENGTH, 16_384];

/// Paired canonical operands, sampled once and reused by each implementation.
struct Inputs<T> {
    lhs: Vec<T>,
    rhs: Vec<T>,
}

/// Keep the corpus determined by modulus and length, with lhs sampled before rhs.
/// Canonical residues also satisfy the corresponding lazy-operation input bounds.
fn inputs<T>(modulus: T, len: usize) -> Inputs<T>
where
    T: Copy + Default + Into<u64> + SampleUniform,
{
    let mut rng = StdRng::seed_from_u64(RNG_SEED ^ modulus.into() ^ len as u64);
    let distribution = Uniform::new(T::default(), modulus).unwrap();
    Inputs {
        lhs: (&distribution).sample_iter(&mut rng).take(len).collect(),
        rhs: (&distribution).sample_iter(&mut rng).take(len).collect(),
    }
}

/// Allocate once, then measure one complete slice operation per iteration.
/// The operation overwrites every output element, so no reset is required.
fn bench_binary_to<T, M>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    lhs: &[T],
    rhs: &[T],
    modulus: M,
    operation: impl Fn(M, &[T], &[T], &mut [T]),
) where
    T: Copy + Default,
    M: Copy,
{
    let mut output = vec![T::default(); lhs.len()];
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter(|| {
            operation(
                modulus,
                black_box(lhs),
                black_box(rhs),
                black_box(&mut output),
            )
        })
    });
}

/// Consume one prepared pair of slices and return one scalar per iteration.
fn bench_dot_product<T, M>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    lhs: &[T],
    rhs: &[T],
    modulus: M,
    operation: impl Fn(M, &[T], &[T]) -> T,
) where
    M: Copy,
{
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter(|| black_box(operation(modulus, black_box(lhs), black_box(rhs))))
    });
}

fn bench_barrett_u32(c: &mut Criterion) {
    let input = inputs(MODULUS_U32, POLY_LENGTH);
    let len = input.lhs.len();
    let modulus = BarrettModulus::new(MODULUS_U32);

    let mut canonical = vec![0; len];
    let mut lazy = vec![0; len];
    modulus.reduce_mul_slice_to(&input.lhs, &input.rhs, &mut canonical);
    modulus.lazy_reduce_mul_slice_to(&input.lhs, &input.rhs, &mut lazy);
    modulus.reduce_once_slice_assign(&mut lazy);
    assert_eq!(canonical, lazy);

    let mut group = c.benchmark_group(format!("barrett/slice/u32/mul/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_binary_to(
        &mut group,
        "canonical",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
    );
    bench_binary_to(
        &mut group,
        "lazy",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b, out| m.lazy_reduce_mul_slice_to(a, b, out),
    );
    group.finish();

    let mut group = c.benchmark_group(format!("barrett/slice/u32/dot_product/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_dot_product(
        &mut group,
        "canonical",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b| m.reduce_dot_product(a, b),
    );
    group.finish();

    let values: Vec<_> = input.rhs.iter().map(|&value| value.max(1)).collect();
    let elementwise_modulus = UintModulus::new(MODULUS_U32);
    let mut batch_output = vec![0; len];
    let mut elementwise_output = vec![0; len];
    modulus.reduce_inv_slice_to(&values, &mut batch_output);
    elementwise_modulus.reduce_inv_slice_to(&values, &mut elementwise_output);
    assert_eq!(batch_output, elementwise_output);

    let mut group = c.benchmark_group(format!("barrett/slice/u32/inverse_to/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    group.bench_function("batch", |b| {
        b.iter(|| modulus.reduce_inv_slice_to(black_box(&values), black_box(&mut batch_output)))
    });
    group.bench_function("elementwise", |b| {
        b.iter(|| {
            elementwise_modulus
                .reduce_inv_slice_to(black_box(&values), black_box(&mut elementwise_output))
        })
    });
    group.finish();
}

fn bench_barrett_u64(c: &mut Criterion) {
    let input = inputs(MODULUS_U64, POLY_LENGTH);
    let len = input.lhs.len();
    let modulus = BarrettModulus::new(MODULUS_U64);

    let mut canonical = vec![0; len];
    let mut lazy = vec![0; len];
    modulus.reduce_mul_slice_to(&input.lhs, &input.rhs, &mut canonical);
    modulus.lazy_reduce_mul_slice_to(&input.lhs, &input.rhs, &mut lazy);
    modulus.reduce_once_slice_assign(&mut lazy);
    assert_eq!(canonical, lazy);

    let mut group = c.benchmark_group(format!("barrett/slice/u64/mul/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_binary_to(
        &mut group,
        "canonical",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
    );
    bench_binary_to(
        &mut group,
        "lazy",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b, out| m.lazy_reduce_mul_slice_to(a, b, out),
    );
    group.finish();

    let mut group = c.benchmark_group(format!("barrett/slice/u64/dot_product/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_dot_product(
        &mut group,
        "canonical",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b| m.reduce_dot_product(a, b),
    );
    group.finish();

    let values: Vec<_> = input.rhs.iter().map(|&value| value.max(1)).collect();
    let elementwise_modulus = UintModulus::new(MODULUS_U64);
    let mut batch_output = vec![0; len];
    let mut elementwise_output = vec![0; len];
    modulus.reduce_inv_slice_to(&values, &mut batch_output);
    elementwise_modulus.reduce_inv_slice_to(&values, &mut elementwise_output);
    assert_eq!(batch_output, elementwise_output);

    let mut group = c.benchmark_group(format!("barrett/slice/u64/inverse_to/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    group.bench_function("batch", |b| {
        b.iter(|| modulus.reduce_inv_slice_to(black_box(&values), black_box(&mut batch_output)))
    });
    group.bench_function("elementwise", |b| {
        b.iter(|| {
            elementwise_modulus
                .reduce_inv_slice_to(black_box(&values), black_box(&mut elementwise_output))
        })
    });
    group.finish();
}

// Canonical pointwise accumulation used by both GLWE and NTRU PBS.
fn pbs_multiply_add<T: primus_integer::FheUint + Into<u64>>(
    c: &mut Criterion,
    q: T,
    lengths: &[usize],
) {
    for &len in lengths {
        let input = inputs(q, len);
        let modulus = BarrettModulus::new(q);
        let mut acc = vec![T::ZERO; len];
        // Keep the addend on its own deterministic stream, independent of lhs/rhs.
        let mut rng = StdRng::seed_from_u64(RNG_SEED ^ 42);
        let addend: Vec<_> = Uniform::new(T::ZERO, q)
            .unwrap()
            .sample_iter(&mut rng)
            .take(len)
            .collect();
        let mut output = vec![T::MAX; len];
        modulus.reduce_mul_add_slice_to(&input.lhs, &input.rhs, &addend, &mut output);
        for (((&a, &b), &c), &actual) in input.lhs.iter().zip(&input.rhs).zip(&addend).zip(&output)
        {
            let expected = (u128::from(a.into()) * u128::from(b.into()) + u128::from(c.into()))
                % u128::from(q.into());
            assert_eq!(u128::from(actual.into()), expected);
        }
        let mut group = c.benchmark_group(format!("barrett/pbs_mac/u{}/q{q}/n{len}", T::BITS));
        group
            .sample_size(20)
            .warm_up_time(std::time::Duration::from_secs(1))
            .measurement_time(std::time::Duration::from_secs(5));
        group.bench_function("dispatched", |b| {
            b.iter(|| {
                modulus.reduce_add_mul_slice_assign(
                    black_box(&mut acc),
                    black_box(&input.lhs),
                    black_box(&input.rhs),
                )
            })
        });
        group.bench_function("scalar", |b| {
            b.iter(|| {
                for ((acc, &lhs), &rhs) in black_box(&mut acc)
                    .iter_mut()
                    .zip(black_box(&input.lhs))
                    .zip(black_box(&input.rhs))
                {
                    *acc = modulus.reduce_mul_add(lhs, rhs, *acc);
                }
            })
        });
        group.bench_function("to", |b| {
            b.iter(|| {
                modulus.reduce_mul_add_slice_to(
                    black_box(&input.lhs),
                    black_box(&input.rhs),
                    black_box(&addend),
                    black_box(&mut output),
                )
            })
        });
        group.finish();
    }
}

// Pointwise products used after the shared blind rotation in factorized MVB.
fn pointwise_multiply<T: primus_integer::FheUint + Into<u64>>(c: &mut Criterion, q: T) {
    for len in [1024, 2048] {
        let input = inputs(q, len);
        let modulus = BarrettModulus::new(q);
        let mut output = vec![T::MAX; len];
        modulus.reduce_mul_slice_to(&input.lhs, &input.rhs, &mut output);
        for ((&a, &b), &actual) in input.lhs.iter().zip(&input.rhs).zip(&output) {
            assert_eq!(
                u128::from(actual.into()),
                u128::from(a.into()) * u128::from(b.into()) % u128::from(q.into())
            );
        }
        let mut group =
            c.benchmark_group(format!("barrett/pointwise_mul/u{}/q{q}/n{len}", T::BITS));
        group
            .sample_size(20)
            .warm_up_time(std::time::Duration::from_secs(1))
            .measurement_time(std::time::Duration::from_secs(5));
        group.bench_function("to", |b| {
            b.iter(|| {
                modulus.reduce_mul_slice_to(
                    black_box(&input.lhs),
                    black_box(&input.rhs),
                    black_box(&mut output),
                );
            })
        });
        group.finish();
    }
}

fn bench_barrett_slice(c: &mut Criterion) {
    pointwise_multiply(c, 132_120_577u32);
    pointwise_multiply(c, 1_125_899_906_826_241u64);
    pointwise_multiply(c, 1_152_921_504_606_830_593u64);

    pbs_multiply_add(c, 132_120_577u32, &[1024, 2048]);
    pbs_multiply_add(c, 1_125_899_906_826_241u64, &[32, 33, 1024, 1025, 2048]);
    // Cover the IFMA cutoff, a large NTT prime, and the Barrett upper bound.
    pbs_multiply_add(c, 1u64 << 50, &[1024]);
    pbs_multiply_add(c, 1_152_921_504_606_830_593u64, &[1024, 2048]);
    pbs_multiply_add(c, (1u64 << 62) - 1, &[1024, 2048]);
    bench_barrett_u32(c);
    bench_barrett_u64(c);

    // Scale the distinct u64 kernels without repeating the production length.
    for len in SCALING_LENGTHS {
        if len == POLY_LENGTH {
            continue;
        }

        let input = inputs(MODULUS_U64, len);
        let modulus = BarrettModulus::new(MODULUS_U64);

        let mut group = c.benchmark_group(format!("barrett/slice/u64/mul/{len}"));
        group.throughput(Throughput::Elements(len as u64));
        bench_binary_to(
            &mut group,
            "canonical",
            &input.lhs,
            &input.rhs,
            modulus,
            |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
        );
        bench_binary_to(
            &mut group,
            "lazy",
            &input.lhs,
            &input.rhs,
            modulus,
            |m, a, b, out| m.lazy_reduce_mul_slice_to(a, b, out),
        );
        group.finish();

        let mut group = c.benchmark_group(format!("barrett/slice/u64/dot_product/{len}"));
        group.throughput(Throughput::Elements(len as u64));
        bench_dot_product(
            &mut group,
            "canonical",
            &input.lhs,
            &input.rhs,
            modulus,
            |m, a, b| m.reduce_dot_product(a, b),
        );
        group.finish();

        let values: Vec<_> = input.rhs.iter().map(|&value| value.max(1)).collect();
        let elementwise_modulus = UintModulus::new(MODULUS_U64);
        let mut batch_output = vec![0; len];
        let mut elementwise_output = vec![0; len];
        modulus.reduce_inv_slice_to(&values, &mut batch_output);
        elementwise_modulus.reduce_inv_slice_to(&values, &mut elementwise_output);
        assert_eq!(batch_output, elementwise_output);

        let mut group = c.benchmark_group(format!("barrett/slice/u64/inverse_to/{len}"));
        group.throughput(Throughput::Elements(len as u64));
        group.bench_function("batch", |b| {
            b.iter(|| modulus.reduce_inv_slice_to(black_box(&values), black_box(&mut batch_output)))
        });
        group.bench_function("elementwise", |b| {
            b.iter(|| {
                elementwise_modulus
                    .reduce_inv_slice_to(black_box(&values), black_box(&mut elementwise_output))
            })
        });
        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    targets = bench_barrett_slice
}
criterion_main!(benches);
