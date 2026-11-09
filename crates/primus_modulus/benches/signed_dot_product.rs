//! cargo bench -p primus_modulus --bench signed_dot_product
//! cargo +nightly bench -p primus_modulus --bench signed_dot_product --features simd

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_integer::{AsFrom, FheUint};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;

fn dot_product<T: FheUint>(c: &mut Criterion, name: &str, modulus: impl RingContext<T>) {
    // Short inputs, full vectors, a scalar tail, and larger repeated buffers.
    for length in [16, 1024, 1025, 4096] {
        let mut state = 0x8356_125f_334d_aaaa_u64;
        let mut lhs = Vec::with_capacity(length);
        let mut signed = Vec::with_capacity(length);
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            lhs.push(modulus.reduce(T::as_from(state)));
            signed.push(T::SignedInteger::as_from((state % 3) as i64 - 1));
        }
        let encoded: Vec<T> = signed.iter().map(|&s| modulus.encode_signed(s)).collect();
        let mut group = c.benchmark_group(format!("slice/signed_dot_product/{name}/{length}"));
        group.throughput(Throughput::Elements(length as u64));
        // Same mathematical input; encoding and allocation are outside timing.
        group.bench_function("encoded", |b| {
            b.iter(|| black_box(modulus).reduce_dot_product(black_box(&lhs), black_box(&encoded)));
        });
        group.bench_function("signed", |b| {
            b.iter(|| {
                black_box(modulus).reduce_dot_product_signed(black_box(&lhs), black_box(&signed))
            });
        });
        group.finish();
    }
}

fn benches(c: &mut Criterion) {
    dot_product(c, "native_u32", NativeModulus::<u32>::new());
    dot_product(c, "native_u64", NativeModulus::<u64>::new());
    dot_product(c, "barrett_u32", BarrettModulus::new(132_120_577u32));
    dot_product(
        c,
        "barrett_u64",
        BarrettModulus::new(1_152_921_504_606_846_977u64),
    );
}

criterion_group!(benchmarks, benches);
criterion_main!(benchmarks);
