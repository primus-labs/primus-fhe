// cargo bench -p primus_integer --bench word_ops

mod support;

use core::hint::black_box;

use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
    measurement::WallTime,
};
use primus_integer::{CarryingMul, UnsignedInteger, WideningMul};
#[cfg(feature = "simd")]
use primus_integer::{SimdArray, SimdUnsignedInteger};
use rand::{Fill, SeedableRng, rngs::StdRng};

use support::{RNG_SEED, random_values};

const BATCH_LEN: usize = 8192;

struct WordInputs<T> {
    lhs: Vec<T>,
    rhs: Vec<T>,
    carry: Vec<T>,
    add: Vec<T>,
}

impl<T> WordInputs<T> {
    fn assert_batch_len(&self) {
        assert_eq!(self.lhs.len(), BATCH_LEN);
        assert_eq!(self.rhs.len(), BATCH_LEN);
        assert_eq!(self.carry.len(), BATCH_LEN);
        assert_eq!(self.add.len(), BATCH_LEN);
    }
}

fn word_inputs<T>(rng: &mut StdRng) -> WordInputs<T>
where
    T: UnsignedInteger + Fill,
{
    WordInputs {
        lhs: random_values(rng, BATCH_LEN),
        rhs: random_values(rng, BATCH_LEN),
        carry: random_values(rng, BATCH_LEN),
        add: random_values(rng, BATCH_LEN),
    }
}

fn bench_scalar_word_ops<T>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    type_name: &str,
    inputs: &WordInputs<T>,
) where
    T: UnsignedInteger,
{
    let mut low = vec![T::ZERO; BATCH_LEN];
    let mut high = vec![T::ZERO; BATCH_LEN];

    group.bench_function(BenchmarkId::new("widening_mul", type_name), |b| {
        b.iter(|| {
            let lhs = black_box(inputs.lhs.as_slice());
            let rhs = black_box(inputs.rhs.as_slice());
            let low = black_box(low.as_mut_slice());
            let high = black_box(high.as_mut_slice());

            let operands = lhs.iter().zip(rhs);
            let outputs = low.iter_mut().zip(high);
            for ((&lhs, &rhs), (low, high)) in operands.zip(outputs) {
                (*low, *high) = WideningMul::widening_mul(lhs, rhs);
            }
        })
    });

    group.bench_function(BenchmarkId::new("widening_mul_hw", type_name), |b| {
        b.iter(|| {
            let lhs = black_box(inputs.lhs.as_slice());
            let rhs = black_box(inputs.rhs.as_slice());
            let high = black_box(high.as_mut_slice());

            for ((&lhs, &rhs), high) in lhs.iter().zip(rhs).zip(high) {
                *high = WideningMul::widening_mul_hw(lhs, rhs);
            }
        })
    });

    group.bench_function(BenchmarkId::new("carrying_mul", type_name), |b| {
        b.iter(|| {
            let lhs = black_box(inputs.lhs.as_slice());
            let rhs = black_box(inputs.rhs.as_slice());
            let carry = black_box(inputs.carry.as_slice());
            let low = black_box(low.as_mut_slice());
            let high = black_box(high.as_mut_slice());

            let operands = lhs.iter().zip(rhs).zip(carry);
            let outputs = low.iter_mut().zip(high);
            for (((&lhs, &rhs), &carry), (low, high)) in operands.zip(outputs) {
                (*low, *high) = CarryingMul::carrying_mul(lhs, rhs, carry);
            }
        })
    });

    group.bench_function(BenchmarkId::new("carrying_mul_hw", type_name), |b| {
        b.iter(|| {
            let lhs = black_box(inputs.lhs.as_slice());
            let rhs = black_box(inputs.rhs.as_slice());
            let carry = black_box(inputs.carry.as_slice());
            let high = black_box(high.as_mut_slice());

            let operands = lhs.iter().zip(rhs).zip(carry);
            for (((&lhs, &rhs), &carry), high) in operands.zip(high) {
                *high = CarryingMul::carrying_mul_hw(lhs, rhs, carry);
            }
        })
    });

    group.bench_function(BenchmarkId::new("carrying_mul_add", type_name), |b| {
        b.iter(|| {
            let lhs = black_box(inputs.lhs.as_slice());
            let rhs = black_box(inputs.rhs.as_slice());
            let carry = black_box(inputs.carry.as_slice());
            let add = black_box(inputs.add.as_slice());
            let low = black_box(low.as_mut_slice());
            let high = black_box(high.as_mut_slice());

            let operands = lhs.iter().zip(rhs).zip(carry).zip(add);
            let outputs = low.iter_mut().zip(high);
            for ((((&lhs, &rhs), &carry), &add), (low, high)) in operands.zip(outputs) {
                (*low, *high) = CarryingMul::carrying_mul_add(lhs, rhs, carry, add);
            }
        })
    });
}

#[cfg(feature = "simd")]
fn bench_simd_word_ops<T>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    type_name: &str,
    inputs: &WordInputs<T>,
) where
    T: SimdUnsignedInteger,
{
    assert_eq!(BATCH_LEN % T::LANE_COUNT, 0);

    let (lhs, lhs_tail) = T::simd_as_chunks(inputs.lhs.as_slice());
    let (rhs, rhs_tail) = T::simd_as_chunks(inputs.rhs.as_slice());
    let (carry, carry_tail) = T::simd_as_chunks(inputs.carry.as_slice());
    let (add, add_tail) = T::simd_as_chunks(inputs.add.as_slice());
    assert!(
        lhs_tail.is_empty() && rhs_tail.is_empty() && carry_tail.is_empty() && add_tail.is_empty()
    );

    let mut low = vec![T::ZERO; BATCH_LEN];
    let mut high = vec![T::ZERO; BATCH_LEN];
    let case = format!("{type_name}x{}", T::LANE_COUNT);

    group.bench_function(BenchmarkId::new("simd_widening_mul", &case), |b| {
        b.iter(|| {
            let lhs = black_box(lhs);
            let rhs = black_box(rhs);
            let low = T::simd_as_chunks_mut(black_box(low.as_mut_slice())).0;
            let high = T::simd_as_chunks_mut(black_box(high.as_mut_slice())).0;

            let operands = lhs.iter().zip(rhs);
            let outputs = low.iter_mut().zip(high);
            for ((lhs, rhs), (low, high)) in operands.zip(outputs) {
                let lhs = T::SimdT::from_array(*lhs);
                let rhs = T::SimdT::from_array(*rhs);
                let (result_low, result_high) = WideningMul::widening_mul(lhs, rhs);
                *low = result_low.to_array();
                *high = result_high.to_array();
            }
        })
    });

    group.bench_function(BenchmarkId::new("simd_widening_mul_hw", &case), |b| {
        b.iter(|| {
            let lhs = black_box(lhs);
            let rhs = black_box(rhs);
            let high = T::simd_as_chunks_mut(black_box(high.as_mut_slice())).0;

            for ((lhs, rhs), high) in lhs.iter().zip(rhs).zip(high) {
                let lhs = T::SimdT::from_array(*lhs);
                let rhs = T::SimdT::from_array(*rhs);
                *high = WideningMul::widening_mul_hw(lhs, rhs).to_array();
            }
        })
    });

    group.bench_function(BenchmarkId::new("simd_carrying_mul", &case), |b| {
        b.iter(|| {
            let lhs = black_box(lhs);
            let rhs = black_box(rhs);
            let carry = black_box(carry);
            let low = T::simd_as_chunks_mut(black_box(low.as_mut_slice())).0;
            let high = T::simd_as_chunks_mut(black_box(high.as_mut_slice())).0;

            let operands = lhs.iter().zip(rhs).zip(carry);
            let outputs = low.iter_mut().zip(high);
            for (((lhs, rhs), carry), (low, high)) in operands.zip(outputs) {
                let lhs = T::SimdT::from_array(*lhs);
                let rhs = T::SimdT::from_array(*rhs);
                let carry = T::SimdT::from_array(*carry);
                let (result_low, result_high) = CarryingMul::carrying_mul(lhs, rhs, carry);
                *low = result_low.to_array();
                *high = result_high.to_array();
            }
        })
    });

    group.bench_function(BenchmarkId::new("simd_carrying_mul_hw", &case), |b| {
        b.iter(|| {
            let lhs = black_box(lhs);
            let rhs = black_box(rhs);
            let carry = black_box(carry);
            let high = T::simd_as_chunks_mut(black_box(high.as_mut_slice())).0;

            let operands = lhs.iter().zip(rhs).zip(carry);
            for (((lhs, rhs), carry), high) in operands.zip(high) {
                let lhs = T::SimdT::from_array(*lhs);
                let rhs = T::SimdT::from_array(*rhs);
                let carry = T::SimdT::from_array(*carry);
                *high = CarryingMul::carrying_mul_hw(lhs, rhs, carry).to_array();
            }
        })
    });

    group.bench_function(BenchmarkId::new("simd_carrying_mul_add", &case), |b| {
        b.iter(|| {
            let lhs = black_box(lhs);
            let rhs = black_box(rhs);
            let carry = black_box(carry);
            let add = black_box(add);
            let low = T::simd_as_chunks_mut(black_box(low.as_mut_slice())).0;
            let high = T::simd_as_chunks_mut(black_box(high.as_mut_slice())).0;

            let operands = lhs.iter().zip(rhs).zip(carry).zip(add);
            let outputs = low.iter_mut().zip(high);
            for ((((lhs, rhs), carry), add), (low, high)) in operands.zip(outputs) {
                let lhs = T::SimdT::from_array(*lhs);
                let rhs = T::SimdT::from_array(*rhs);
                let carry = T::SimdT::from_array(*carry);
                let add = T::SimdT::from_array(*add);
                let (result_low, result_high) = CarryingMul::carrying_mul_add(lhs, rhs, carry, add);
                *low = result_low.to_array();
                *high = result_high.to_array();
            }
        })
    });
}

fn bench_word_ops(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    // Full-width values make high halves and carry outputs common, as they are
    // in Barrett/Shoup reduction and CRT accumulation.
    let u32_inputs = word_inputs::<u32>(&mut rng);
    let u64_inputs = word_inputs::<u64>(&mut rng);
    u32_inputs.assert_batch_len();
    u64_inputs.assert_batch_len();

    let mut group = c.benchmark_group("word_ops");
    group.throughput(Throughput::Elements(BATCH_LEN as u64));

    // These batched scalar-API cases intentionally allow compiler
    // auto-vectorization; they measure optimized slice throughput.
    bench_scalar_word_ops(&mut group, "u32", &u32_inputs);
    bench_scalar_word_ops(&mut group, "u64", &u64_inputs);

    #[cfg(feature = "simd")]
    {
        bench_simd_word_ops(&mut group, "u32", &u32_inputs);
        bench_simd_word_ops(&mut group, "u64", &u64_inputs);
    }

    group.finish();
}

criterion_group!(benches, bench_word_ops);
criterion_main!(benches);
