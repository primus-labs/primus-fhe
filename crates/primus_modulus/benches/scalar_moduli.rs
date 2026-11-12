//! Run with `cargo bench -p primus_modulus --bench scalar_moduli`.
//! Filter on `barrett/scalar` for the canonical and lazy Barrett workloads.

use core::{hint::black_box, time::Duration};

use criterion::{
    BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, CompactModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::prelude::*;
use rand::{
    SeedableRng,
    distr::{Distribution, Uniform},
    rngs::StdRng,
};

const RNG_SEED: u64 = 0x6d6f_6475_6c75_735f;
const MODULUS_U32: u32 = 1_073_692_673;
const MODULUS_U64: u64 = 1_125_899_906_826_241;
const INPUT_COUNT: usize = 1_024;
const POWER_OF_TWO_U64: u64 = 1 << 50;

/// Paired canonical operands, sampled once and reused by each implementation.
struct Inputs<T> {
    lhs: Vec<T>,
    rhs: Vec<T>,
}

impl<T: Copy> Inputs<T> {
    fn pairs(&self) -> impl Iterator<Item = (T, T)> + Clone + '_ {
        self.lhs.iter().copied().zip(self.rhs.iter().copied())
    }
}

/// Keep the corpus determined by modulus and length, with lhs sampled before rhs.
fn inputs<T: FheUint + Into<u64>>(modulus: T, len: usize) -> Inputs<T> {
    let mut rng = StdRng::seed_from_u64(RNG_SEED ^ modulus.into() ^ len as u64);
    let distribution = Uniform::new(T::ZERO, modulus).unwrap();
    Inputs {
        lhs: (&distribution).sample_iter(&mut rng).take(len).collect(),
        rhs: (&distribution).sample_iter(&mut rng).take(len).collect(),
    }
}

/// Select prepared operands outside timing. One iteration measures one scalar operation.
fn bench_scalar<T, M: Copy, R>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    inputs: impl Iterator<Item = T> + Clone,
    modulus: M,
    operation: impl Fn(M, T) -> R,
) {
    let mut inputs = inputs.cycle();
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter_batched(
            || inputs.next().expect("scalar benchmark requires operands"),
            |value| black_box(operation(modulus, value)),
            BatchSize::SmallInput,
        )
    });
}

fn bench_binary<T: Copy, M: Copy>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    input: &Inputs<T>,
    modulus: M,
    operation: impl Fn(M, T, T) -> T,
) {
    bench_scalar(group, name, input.pairs(), modulus, |m, (lhs, rhs)| {
        operation(m, black_box(lhs), black_box(rhs))
    });
}

/// Combine a canonical high part and low bits to exercise full-width reduction.
fn full_words<T: FheUint>(input: &Inputs<T>, low_bits: u32) -> Vec<T> {
    let mask = (T::ONE << low_bits) - T::ONE;
    input
        .pairs()
        .map(|(high, low)| (high << low_bits) | (low & mask))
        .collect()
}

fn bench_barrett_word<T: FheUint>(
    c: &mut Criterion,
    modulus: BarrettModulus<T>,
    input: &Inputs<T>,
    full_width: &[T],
) {
    assert_eq!(
        modulus.reduce_once(modulus.lazy_reduce(full_width[0])),
        modulus.reduce(full_width[0])
    );
    assert_eq!(
        modulus.reduce_once(modulus.lazy_reduce_mul(input.lhs[0], input.rhs[0])),
        modulus.reduce_mul(input.lhs[0], input.rhs[0])
    );

    let width = T::BITS;
    let mut group = c.benchmark_group(format!("barrett/scalar/u{width}/reduce_word"));
    bench_scalar(
        &mut group,
        "canonical",
        full_width.iter().copied(),
        modulus,
        |m, x| m.reduce(black_box(x)),
    );
    bench_scalar(
        &mut group,
        "lazy",
        full_width.iter().copied(),
        modulus,
        |m, x| m.lazy_reduce(black_box(x)),
    );
    group.finish();

    let mut group = c.benchmark_group(format!("barrett/scalar/u{width}/mul"));
    bench_binary(&mut group, "canonical", input, modulus, |m, a, b| {
        m.reduce_mul(a, b)
    });
    bench_binary(&mut group, "lazy", input, modulus, |m, a, b| {
        m.lazy_reduce_mul(a, b)
    });
    group.finish();
}

fn bench_barrett(c: &mut Criterion, input_u64: &Inputs<u64>) {
    let input_u32 = inputs(MODULUS_U32, INPUT_COUNT);
    bench_barrett_word(
        c,
        BarrettModulus::new(MODULUS_U32),
        &input_u32,
        &full_words(&input_u32, 2),
    );

    let modulus = BarrettModulus::new(MODULUS_U64);
    let full_width = full_words(input_u64, 14);
    bench_barrett_word(c, modulus, input_u64, &full_width);

    let (multi_limb, remainder) = full_width.as_chunks::<4>();
    assert!(remainder.is_empty());
    let mut group = c.benchmark_group("barrett/scalar/u64/reduce_multi_limb");
    bench_scalar(
        &mut group,
        "4_limbs_canonical",
        multi_limb.iter().copied(),
        modulus,
        |m, x| m.reduce(black_box(x).as_slice()),
    );
    bench_scalar(
        &mut group,
        "4_limbs_lazy",
        multi_limb.iter().copied(),
        modulus,
        |m, x| m.lazy_reduce(black_box(x).as_slice()),
    );
    group.finish();
}

fn bench_general_u64(c: &mut Criterion, input: &Inputs<u64>) {
    let compact = CompactModulus::new(MODULUS_U64);
    let uint = UintModulus::new(MODULUS_U64);

    assert_eq!(
        compact.reduce_add(input.lhs[0], input.rhs[0]),
        uint.reduce_add(input.lhs[0], input.rhs[0])
    );

    let mut group = c.benchmark_group("scalar/general/u64/add");
    bench_binary(&mut group, "compact", input, compact, |m, a, b| {
        m.reduce_add(a, b)
    });
    bench_binary(&mut group, "uint", input, uint, |m, a, b| {
        m.reduce_add(a, b)
    });
    group.finish();

    let mut group = c.benchmark_group("scalar/general/u64/sub");
    bench_binary(&mut group, "compact", input, compact, |m, a, b| {
        m.reduce_sub(a, b)
    });
    bench_binary(&mut group, "uint", input, uint, |m, a, b| {
        m.reduce_sub(a, b)
    });
    group.finish();
}

fn bench_power_of_two_u64(c: &mut Criterion) {
    let input = inputs(POWER_OF_TWO_U64, INPUT_COUNT);
    let native = NativeModulus::<u64>::new();
    let power_of_two = PowOf2Modulus::new(POWER_OF_TWO_U64);

    let mut group = c.benchmark_group("scalar/power_of_two/u64/add");
    bench_binary(&mut group, "native", &input, native, |m, a, b| {
        m.reduce_add(a, b)
    });
    bench_binary(&mut group, "pow_of_2", &input, power_of_two, |m, a, b| {
        m.reduce_add(a, b)
    });
    group.finish();

    let mut group = c.benchmark_group("scalar/power_of_two/u64/mul");
    bench_binary(&mut group, "native", &input, native, |m, a, b| {
        m.reduce_mul(a, b)
    });
    bench_binary(&mut group, "pow_of_2", &input, power_of_two, |m, a, b| {
        m.reduce_mul(a, b)
    });
    group.finish();
}

fn bench_scalar_moduli(c: &mut Criterion) {
    let input_u64 = inputs(MODULUS_U64, INPUT_COUNT);
    bench_barrett(c, &input_u64);
    bench_general_u64(c, &input_u64);
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
