use algebra::modulus::PowOf2Modulus;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use lattice::LWE;
use rand::prelude::*;
use rand_distr::Uniform;

const N: usize = 512;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let rr_dis = Uniform::new(0, 1024);
    let modulus = <PowOf2Modulus<u32>>::new(1024u32);

    let a0: Vec<u32> = rr_dis.sample_iter(&mut rng).take(N).collect();
    let a1: Vec<u32> = rr_dis.sample_iter(&mut rng).take(N).collect();

    let b0 = rr_dis.sample(&mut rng);
    let b1 = rr_dis.sample(&mut rng);

    let mut c0 = <LWE<u32>>::new(a0, b0);
    let c1 = <LWE<u32>>::new(a1, b1);

    let mut group = c.benchmark_group("LWE");

    group.bench_function("LWE add component wise clone", |b| {
        b.iter_batched(
            || c0.clone(),
            |c0| c0.add_component_wise(black_box(&c1)),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("LWE add component wise collect", |b| {
        b.iter(|| black_box(&c0).add_component_wise_ref(black_box(&c1)))
    });

    group.bench_function("LWE add reduce component wise clone", |b| {
        b.iter_batched(
            || c0.clone(),
            |c0| c0.add_reduce_component_wise(black_box(&c1), black_box(modulus)),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("LWE add reduce component wise collect", |b| {
        b.iter(|| black_box(&c0).add_reduce_component_wise_ref(black_box(&c1), black_box(modulus)))
    });

    group.bench_function("LWE sub component wise clone", |b| {
        b.iter_batched(
            || c0.clone(),
            |c0| c0.sub_component_wise(black_box(&c1)),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("LWE sub component wise collect", |b| {
        b.iter(|| black_box(&c0).sub_component_wise_ref(black_box(&c1)))
    });

    group.bench_function("LWE sub reduce component wise clone", |b| {
        b.iter_batched(
            || c0.clone(),
            |c0| c0.sub_reduce_component_wise(black_box(&c1), black_box(modulus)),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("LWE sub reduce component wise collect", |b| {
        b.iter(|| black_box(&c0).sub_reduce_component_wise_ref(black_box(&c1), black_box(modulus)))
    });

    group.bench_function("LWE add inplace component wise", |b| {
        b.iter(|| black_box(&mut c0).add_component_wise_assign(black_box(&c1)))
    });

    group.bench_function("LWE sub inplace component wise", |b| {
        b.iter(|| black_box(&mut c0).sub_component_wise_assign(black_box(&c1)))
    });

    group.bench_function("LWE add reduce inplace component wise", |b| {
        b.iter(|| {
            black_box(&mut c0).add_reduce_component_wise_assign(black_box(&c1), black_box(modulus))
        })
    });

    group.bench_function("LWE sub reduce inplace component wise", |b| {
        b.iter(|| {
            black_box(&mut c0).sub_reduce_inplace_component_wise(black_box(&c1), black_box(modulus))
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
