//! Run with `cargo bench -p primus_modulus --bench scalar_moduli`.

use core::{hint::black_box, time::Duration};

use criterion::{
    BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::Measurement,
};
use primus_modulus::{CompactModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::prelude::*;
use rand::{
    SeedableRng,
    distr::{Distribution, Uniform, uniform::SampleUniform},
    rngs::StdRng,
};

const RNG_SEED: u64 = 0x6d6f_6475_6c75_735f;
const MODULUS_U64: u64 = 1_125_899_906_826_241;
const INPUT_COUNT: usize = 1_024;
const POWER_OF_TWO_U64: u64 = 1 << 50;

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

fn bench_general_u64(c: &mut Criterion) {
    let input = inputs(MODULUS_U64, INPUT_COUNT);
    let compact = CompactModulus::new(MODULUS_U64);
    let uint = UintModulus::new(MODULUS_U64);

    assert_eq!(
        compact.reduce_add(input.lhs[0], input.rhs[0]),
        uint.reduce_add(input.lhs[0], input.rhs[0])
    );

    let mut group = c.benchmark_group("scalar/general/u64/add");
    bench_binary(
        &mut group,
        "compact",
        &input.lhs,
        &input.rhs,
        compact,
        |m, a, b| m.reduce_add(a, b),
    );
    bench_binary(
        &mut group,
        "uint",
        &input.lhs,
        &input.rhs,
        uint,
        |m, a, b| m.reduce_add(a, b),
    );
    group.finish();

    let mut group = c.benchmark_group("scalar/general/u64/sub");
    bench_binary(
        &mut group,
        "compact",
        &input.lhs,
        &input.rhs,
        compact,
        |m, a, b| m.reduce_sub(a, b),
    );
    bench_binary(
        &mut group,
        "uint",
        &input.lhs,
        &input.rhs,
        uint,
        |m, a, b| m.reduce_sub(a, b),
    );
    group.finish();
}

fn bench_power_of_two_u64(c: &mut Criterion) {
    let input = inputs(POWER_OF_TWO_U64, INPUT_COUNT);
    let native = NativeModulus::<u64>::new();
    let power_of_two = PowOf2Modulus::new(POWER_OF_TWO_U64);

    let mut group = c.benchmark_group("scalar/power_of_two/u64/add");
    bench_binary(
        &mut group,
        "native",
        &input.lhs,
        &input.rhs,
        native,
        |m, a, b| m.reduce_add(a, b),
    );
    bench_binary(
        &mut group,
        "pow_of_2",
        &input.lhs,
        &input.rhs,
        power_of_two,
        |m, a, b| m.reduce_add(a, b),
    );
    group.finish();

    let mut group = c.benchmark_group("scalar/power_of_two/u64/mul");
    bench_binary(
        &mut group,
        "native",
        &input.lhs,
        &input.rhs,
        native,
        |m, a, b| m.reduce_mul(a, b),
    );
    bench_binary(
        &mut group,
        "pow_of_2",
        &input.lhs,
        &input.rhs,
        power_of_two,
        |m, a, b| m.reduce_mul(a, b),
    );
    group.finish();
}

fn bench_scalar_moduli(c: &mut Criterion) {
    bench_general_u64(c);
    bench_power_of_two_u64(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    targets = bench_scalar_moduli
}
criterion_main!(benches);
