use std::hint::black_box;

use algebra::arith::Xgcd;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::{distributions::Uniform, thread_rng, Rng};

pub fn criterion_benchmark(c: &mut Criterion) {
    let modulus = 132120577u32;
    let mut rng = thread_rng();
    let dis = Uniform::new(0, modulus);

    c.bench_function("gcd", |b| {
        b.iter_batched(
            || rng.sample(dis),
            |v| Xgcd::gcd(black_box(v), black_box(modulus)),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("xgcd", |b| {
        b.iter_batched(
            || rng.sample(dis),
            |v| Xgcd::xgcd(black_box(modulus), black_box(v)),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("gcdinv", |b| {
        b.iter_batched(
            || rng.sample(dis),
            |v| Xgcd::gcdinv(black_box(v), black_box(modulus)),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
