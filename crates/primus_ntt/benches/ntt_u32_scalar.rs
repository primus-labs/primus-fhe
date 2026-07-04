mod common;

use criterion::{Criterion, criterion_group, criterion_main};

fn bench(c: &mut Criterion) {
    common::bench_u32::bench_scalar(c);
}

criterion_group! {
    name = benches;
    config = common::bench_u32::quick_criterion();
    targets = bench
}
criterion_main!(benches);
