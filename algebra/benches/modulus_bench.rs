use algebra::{
    modulus::{to_monty, *},
    reduce::*,
};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::prelude::*;
use rand_distr::Uniform;

const BARRETT_U32_P: u32 = 1073707009;
const BABY_BEAR_P: u32 = 0x78000001;
const BARRETT_U64_P: u64 = 1152921504606830593;
const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

fn bench_u32_barrett_modulus(c: &mut Criterion) {
    let barrett = <BarrettModulus<u32>>::new(BARRETT_U32_P);

    let all: Uniform<u32> = Uniform::new(0, BARRETT_U32_P);
    let positive = Uniform::new(1, BARRETT_U32_P);

    let setup_two = || -> (u32, u32) {
        (
            all.sample(&mut thread_rng()),
            positive.sample(&mut thread_rng()),
        )
    };
    let setup_one = || -> u32 { positive.sample(&mut thread_rng()) };

    let mut group = c.benchmark_group("u32 barrett modulus");

    group.bench_function("u32 barrett modulus add", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.add_reduce(y, barrett),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("u32 barrett modulus sub", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.sub_reduce(y, barrett),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("u32 barrett modulus mul", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.mul_reduce(y, barrett),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("u32 barrett modulus neg", |b| {
        b.iter_batched(setup_one, |y| y.neg_reduce(barrett), BatchSize::SmallInput)
    });

    group.bench_function("u32 barrett modulus reduce", |b| {
        b.iter_batched(setup_one, |y| y.reduce(barrett), BatchSize::SmallInput)
    });

    group.bench_function("u32 barrett modulus inv", |b| {
        b.iter_batched(setup_one, |y| y.inv_reduce(barrett), BatchSize::SmallInput)
    });

    group.bench_function("u32 barrett modulus div", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.div_reduce(y, barrett),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_baby_bear_modulus(c: &mut Criterion) {
    let all: Uniform<u32> = Uniform::new(0, BABY_BEAR_P);
    let positive = Uniform::new(1, BABY_BEAR_P);

    let setup_two = || -> (u32, u32) {
        (
            to_monty(all.sample(&mut thread_rng())),
            to_monty(positive.sample(&mut thread_rng())),
        )
    };
    let setup_one = || -> u32 { to_monty(positive.sample(&mut thread_rng())) };

    let mut group = c.benchmark_group("baby bear modulus");

    group.bench_function("baby bear modulus add", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.add_reduce(y, BabyBearModulus),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("baby bear modulus sub", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.sub_reduce(y, BabyBearModulus),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("baby bear modulus mul", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.mul_reduce(y, BabyBearModulus),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("baby bear modulus neg", |b| {
        b.iter_batched(
            setup_one,
            |y| y.neg_reduce(BabyBearModulus),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("baby bear modulus inv", |b| {
        b.iter_batched(
            setup_one,
            |y| y.inv_reduce(BabyBearModulus),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("baby bear modulus div", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.div_reduce(y, BabyBearModulus),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_u64_barrett_modulus(c: &mut Criterion) {
    let barrett = <BarrettModulus<u64>>::new(BARRETT_U64_P);

    let all: Uniform<u64> = Uniform::new(0, BARRETT_U64_P);
    let positive = Uniform::new(1, BARRETT_U64_P);

    let setup_two = || -> (u64, u64) {
        (
            all.sample(&mut thread_rng()),
            positive.sample(&mut thread_rng()),
        )
    };
    let setup_one = || -> u64 { positive.sample(&mut thread_rng()) };

    let mut group = c.benchmark_group("u64 barrett modulus");

    group.bench_function("u64 barrett modulus add", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.add_reduce(y, barrett),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("u64 barrett modulus sub", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.sub_reduce(y, barrett),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("u64 barrett modulus mul", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.mul_reduce(y, barrett),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("u64 barrett modulus neg", |b| {
        b.iter_batched(setup_one, |y| y.neg_reduce(barrett), BatchSize::SmallInput)
    });

    group.bench_function("u64 barrett modulus reduce", |b| {
        b.iter_batched(setup_one, |y| y.reduce(barrett), BatchSize::SmallInput)
    });

    group.bench_function("u64 barrett modulus inv", |b| {
        b.iter_batched(setup_one, |y| y.inv_reduce(barrett), BatchSize::SmallInput)
    });

    group.bench_function("u64 barrett modulus div", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.div_reduce(y, barrett),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

pub fn bench_goldilocks_modulus(c: &mut Criterion) {
    let all: Uniform<u64> = Uniform::new(0, GOLDILOCKS_P);
    let positive = Uniform::new(1, GOLDILOCKS_P);

    let setup_two = || -> (u64, u64) {
        (
            all.sample(&mut thread_rng()),
            positive.sample(&mut thread_rng()),
        )
    };
    let setup_one = || -> u64 { positive.sample(&mut thread_rng()) };

    let mut group = c.benchmark_group("goldilocks modulus");

    group.bench_function("goldilocks modulus add", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.add_reduce(y, GoldilocksModulus),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("goldilocks modulus sub", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.sub_reduce(y, GoldilocksModulus),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("goldilocks modulus mul", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.mul_reduce(y, GoldilocksModulus),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("goldilocks modulus neg", |b| {
        b.iter_batched(
            setup_one,
            |y| y.neg_reduce(GoldilocksModulus),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("goldilocks modulus reduce", |b| {
        b.iter_batched(
            setup_one,
            |y| y.reduce(GoldilocksModulus),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("goldilocks modulus inv", |b| {
        b.iter_batched(
            setup_one,
            |y| y.inv_reduce(GoldilocksModulus),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("goldilocks modulus div", |b| {
        b.iter_batched(
            setup_two,
            |(x, y)| x.div_reduce(y, GoldilocksModulus),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_u32_barrett_modulus,
    bench_baby_bear_modulus,
    bench_u64_barrett_modulus,
    bench_goldilocks_modulus,
);
criterion_main!(benches);
