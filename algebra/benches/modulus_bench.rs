use algebra::{modulus::*, reduce::*};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::prelude::*;

const BARRETT_U32_P: u32 = 1073707009;
const BABY_BEAR_P: u32 = 0x78000001;
const BARRETT_U64_P: u64 = 1152921504606830593;
const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = thread_rng();

    let u32_barrett = <BarrettModulus<u32>>::new(BARRETT_U32_P);

    let x = rng.gen_range(0..BARRETT_U32_P);
    let y = rng.gen_range(1..BARRETT_U32_P);

    let mut group = c.benchmark_group("u32 barrett modulus");

    group.bench_function("u32 barrett modulus add", |b| {
        b.iter(|| black_box(x).add_reduce(black_box(y), u32_barrett))
    });

    group.bench_function("u32 barrett modulus sub", |b| {
        b.iter(|| black_box(x).sub_reduce(black_box(y), u32_barrett))
    });

    group.bench_function("u32 barrett modulus mul", |b| {
        b.iter(|| black_box(x).mul_reduce(black_box(y), u32_barrett))
    });

    group.bench_function("u32 barrett modulus neg", |b| {
        b.iter(|| black_box(x).neg_reduce(u32_barrett))
    });

    group.bench_function("u32 barrett modulus reduce", |b| {
        b.iter(|| black_box(x).reduce(u32_barrett))
    });

    group.bench_function("u32 barrett modulus inv", |b| {
        b.iter(|| black_box(y).inv_reduce(u32_barrett))
    });

    group.bench_function("u32 barrett modulus div", |b| {
        b.iter(|| black_box(x).div_reduce(black_box(y), u32_barrett))
    });

    group.finish();

    let x = rng.gen_range(0..BABY_BEAR_P);
    let y = rng.gen_range(1..BABY_BEAR_P);

    let mut group = c.benchmark_group("baby bear modulus");

    group.bench_function("baby bear modulus add", |b| {
        b.iter(|| black_box(x).add_reduce(black_box(y), BabyBearModulus))
    });

    group.bench_function("baby bear modulus sub", |b| {
        b.iter(|| black_box(x).sub_reduce(black_box(y), BabyBearModulus))
    });

    group.bench_function("baby bear modulus mul", |b| {
        b.iter(|| black_box(x).mul_reduce(black_box(y), BabyBearModulus))
    });

    group.bench_function("baby bear modulus neg", |b| {
        b.iter(|| black_box(x).neg_reduce(BabyBearModulus))
    });

    group.bench_function("baby bear modulus inv", |b| {
        b.iter(|| black_box(y).inv_reduce(BabyBearModulus))
    });

    group.bench_function("baby bear modulus div", |b| {
        b.iter(|| black_box(x).div_reduce(black_box(y), BabyBearModulus))
    });

    group.finish();

    let u64_barrett = <BarrettModulus<u64>>::new(BARRETT_U64_P);

    let x = rng.gen_range(0..BARRETT_U64_P);
    let y = rng.gen_range(1..BARRETT_U64_P);

    let mut group = c.benchmark_group("u64 barrett modulus");

    group.bench_function("u64 barrett modulus add", |b| {
        b.iter(|| black_box(x).add_reduce(black_box(y), u64_barrett))
    });

    group.bench_function("u64 barrett modulus sub", |b| {
        b.iter(|| black_box(x).sub_reduce(black_box(y), u64_barrett))
    });

    group.bench_function("u64 barrett modulus mul", |b| {
        b.iter(|| black_box(x).mul_reduce(black_box(y), u64_barrett))
    });

    group.bench_function("u64 barrett modulus neg", |b| {
        b.iter(|| black_box(x).neg_reduce(u64_barrett))
    });

    group.bench_function("u64 barrett modulus reduce", |b| {
        b.iter(|| black_box(x).reduce(u64_barrett))
    });

    group.bench_function("u64 barrett modulus inv", |b| {
        b.iter(|| black_box(y).inv_reduce(u64_barrett))
    });

    group.bench_function("u64 barrett modulus div", |b| {
        b.iter(|| black_box(x).div_reduce(black_box(y), u64_barrett))
    });

    group.finish();

    let mut group = c.benchmark_group("goldilocks modulus");

    let x = rng.gen_range(0..GOLDILOCKS_P);
    let y = rng.gen_range(1..GOLDILOCKS_P);

    group.bench_function("goldilocks modulus add", |b| {
        b.iter(|| black_box(x).add_reduce(black_box(y), GoldilocksModulus))
    });

    group.bench_function("goldilocks modulus sub", |b| {
        b.iter(|| black_box(x).sub_reduce(black_box(y), GoldilocksModulus))
    });

    group.bench_function("goldilocks modulus mul", |b| {
        b.iter(|| black_box(x).mul_reduce(black_box(y), GoldilocksModulus))
    });

    group.bench_function("goldilocks modulus neg", |b| {
        b.iter(|| black_box(x).neg_reduce(GoldilocksModulus))
    });

    group.bench_function("goldilocks modulus reduce", |b| {
        b.iter(|| black_box(x).reduce(GoldilocksModulus))
    });

    group.bench_function("goldilocks modulus inv", |b| {
        b.iter(|| black_box(y).inv_reduce(GoldilocksModulus))
    });

    group.bench_function("goldilocks modulus div", |b| {
        b.iter(|| black_box(x).div_reduce(black_box(y), GoldilocksModulus))
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
