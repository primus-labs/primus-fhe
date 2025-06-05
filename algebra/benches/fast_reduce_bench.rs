use std::hint::black_box;

use algebra::reduce::{ReduceAdd, ReduceDouble, ReduceNeg, ReduceSub, TryReduceInv};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::{distributions::Uniform, thread_rng, Rng};

pub fn criterion_benchmark(c: &mut Criterion) {
    let modulus = 132120577u32;
    let mut rng = thread_rng();
    let dis = Uniform::new(0, modulus);

    c.bench_function("primitive reduce add", |b| {
        b.iter_batched(
            || (rng.sample(dis), rng.sample(dis)),
            |(a, b)| modulus.reduce_add(black_box(a), black_box(b)),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("primitive reduce double", |b| {
        b.iter_batched(
            || rng.sample(dis),
            |a| modulus.reduce_double(black_box(a)),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("primitive reduce sub", |b| {
        b.iter_batched(
            || (rng.sample(dis), rng.sample(dis)),
            |(a, b)| modulus.reduce_sub(black_box(a), black_box(b)),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("primitive reduce neg", |b| {
        b.iter_batched(
            || rng.sample(dis),
            |a| modulus.reduce_neg(black_box(a)),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("primitive reduce try inv", |b| {
        b.iter_batched(
            || rng.sample(dis),
            |a| modulus.try_reduce_inv(black_box(a)),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
