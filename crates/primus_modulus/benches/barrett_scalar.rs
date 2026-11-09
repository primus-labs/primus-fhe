//! Run with `cargo bench -p primus_modulus --bench barrett_scalar`.

use core::{hint::black_box, time::Duration};

use criterion::{
    BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::Measurement,
};
use primus_modulus::BarrettModulus;
use primus_reduce::prelude::*;
use rand::{
    SeedableRng,
    distr::{Distribution, Uniform, uniform::SampleUniform},
    rngs::StdRng,
};

const RNG_SEED: u64 = 0x6d6f_6475_6c75_735f;
const MODULUS_U32: u32 = 1_073_692_673;
const MODULUS_U64: u64 = 1_125_899_906_826_241;
const INPUT_COUNT: usize = 1_024;

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

/// Cycle through prepared operand pairs outside timing; each measured call
/// performs exactly one scalar operation, with Criterion batching its setup.
fn bench_binary<T, M>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    lhs: &[T],
    rhs: &[T],
    modulus: M,
    operation: impl Fn(M, T, T) -> T,
) where
    T: Copy,
    M: Copy,
{
    assert_eq!(lhs.len(), rhs.len(), "scalar benchmark length mismatch");
    assert!(!lhs.is_empty(), "scalar benchmark inputs must be non-empty");

    let mut inputs = lhs.iter().copied().zip(rhs.iter().copied()).cycle();
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter_batched(
            || {
                inputs
                    .next()
                    .expect("scalar benchmark inputs must be non-empty")
            },
            |(lhs, rhs)| black_box(operation(modulus, black_box(lhs), black_box(rhs))),
            BatchSize::SmallInput,
        )
    });
}

/// Select a prepared word or limb array outside timing, then measure one reduction.
fn bench_unary<T, M, R>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    input: &[T],
    modulus: M,
    operation: impl Fn(M, T) -> R,
) where
    T: Copy,
    M: Copy,
{
    assert!(
        !input.is_empty(),
        "scalar benchmark inputs must be non-empty"
    );

    let mut inputs = input.iter().copied().cycle();
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter_batched(
            || {
                inputs
                    .next()
                    .expect("scalar benchmark inputs must be non-empty")
            },
            |value| black_box(operation(modulus, black_box(value))),
            BatchSize::SmallInput,
        )
    });
}

fn bench_barrett_u32(c: &mut Criterion) {
    let input = inputs(MODULUS_U32, INPUT_COUNT);
    let full_width: Vec<_> = input
        .lhs
        .iter()
        .zip(&input.rhs)
        .map(|(&high, &low)| (high << 2) | (low & 3))
        .collect();
    let modulus = BarrettModulus::new(MODULUS_U32);

    assert_eq!(
        modulus.reduce_once(modulus.lazy_reduce(full_width[0])),
        modulus.reduce(full_width[0])
    );
    assert_eq!(
        modulus.reduce_once(modulus.lazy_reduce_mul(input.lhs[0], input.rhs[0])),
        modulus.reduce_mul(input.lhs[0], input.rhs[0])
    );

    let mut group = c.benchmark_group("barrett/scalar/u32/reduce_word");
    bench_unary(&mut group, "canonical", &full_width, modulus, |m, x| {
        m.reduce(x)
    });
    bench_unary(&mut group, "lazy", &full_width, modulus, |m, x| {
        m.lazy_reduce(x)
    });
    group.finish();

    let mut group = c.benchmark_group("barrett/scalar/u32/mul");
    bench_binary(
        &mut group,
        "canonical",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b| m.reduce_mul(a, b),
    );
    bench_binary(
        &mut group,
        "lazy",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b| m.lazy_reduce_mul(a, b),
    );
    group.finish();
}

fn bench_barrett_u64(c: &mut Criterion) {
    let input = inputs(MODULUS_U64, INPUT_COUNT);
    let full_width: Vec<_> = input
        .lhs
        .iter()
        .zip(&input.rhs)
        .map(|(&high, &low)| (high << 14) | (low & ((1 << 14) - 1)))
        .collect();
    let modulus = BarrettModulus::new(MODULUS_U64);

    assert_eq!(
        modulus.reduce_once(modulus.lazy_reduce(full_width[0])),
        modulus.reduce(full_width[0])
    );
    assert_eq!(
        modulus.reduce_once(modulus.lazy_reduce_mul(input.lhs[0], input.rhs[0])),
        modulus.reduce_mul(input.lhs[0], input.rhs[0])
    );

    let mut group = c.benchmark_group("barrett/scalar/u64/reduce_word");
    bench_unary(&mut group, "canonical", &full_width, modulus, |m, x| {
        m.reduce(x)
    });
    bench_unary(&mut group, "lazy", &full_width, modulus, |m, x| {
        m.lazy_reduce(x)
    });
    group.finish();

    let mut group = c.benchmark_group("barrett/scalar/u64/mul");
    bench_binary(
        &mut group,
        "canonical",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b| m.reduce_mul(a, b),
    );
    bench_binary(
        &mut group,
        "lazy",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b| m.lazy_reduce_mul(a, b),
    );
    group.finish();
}

fn bench_multi_limb_reduction(c: &mut Criterion) {
    let input = inputs(MODULUS_U64, INPUT_COUNT);
    let full_width: Vec<_> = input
        .lhs
        .iter()
        .zip(&input.rhs)
        .map(|(&high, &low)| (high << 14) | (low & ((1 << 14) - 1)))
        .collect();
    let (multi_limb, remainder) = full_width.as_chunks::<4>();
    assert!(remainder.is_empty());
    let multi_limb = multi_limb.to_vec();
    let modulus = BarrettModulus::new(MODULUS_U64);

    let mut group = c.benchmark_group("barrett/scalar/u64/reduce_multi_limb");
    bench_unary(
        &mut group,
        "4_limbs_canonical",
        &multi_limb,
        modulus,
        |m, x| m.reduce(x.as_slice()),
    );
    bench_unary(&mut group, "4_limbs_lazy", &multi_limb, modulus, |m, x| {
        m.lazy_reduce(x.as_slice())
    });
    group.finish();
}

fn bench_barrett_scalar(c: &mut Criterion) {
    bench_barrett_u32(c);
    bench_barrett_u64(c);
    bench_multi_limb_reduction(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    targets = bench_barrett_scalar
}
criterion_main!(benches);
