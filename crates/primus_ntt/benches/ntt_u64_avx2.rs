mod common;

use criterion::{Criterion, criterion_group, criterion_main};

fn bench(c: &mut Criterion) {
    common::bench_u64::bench_avx2(c);
}

criterion_group! {
    name = benches;
    config = common::bench_u64::quick_criterion();
    targets = bench
}
criterion_main!(benches);
