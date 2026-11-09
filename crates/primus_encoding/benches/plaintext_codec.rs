//! Coefficient throughput and scalar-call cost with reusable codecs and buffers.
//! Inputs sample across the plaintext/ciphertext ranges, including the centered
//! boundary. In-place decoding restores its input outside timing in fixed batches.

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_encoding::{PlaintextEmbedding, RoundedCodec, ScaledCodec};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus, UintModulus};
use std::hint::black_box;

macro_rules! with_modulus {
    ($q:expr, $modulus:ident, $body:block) => {
        match $q {
            None => {
                let $modulus = NativeModulus::new();
                $body
            }
            Some(q) if q.is_power_of_two() => {
                let $modulus = PowOf2Modulus::new(q);
                $body
            }
            Some(q) if q.leading_zeros() > 1 => {
                let $modulus = BarrettModulus::new(q);
                $body
            }
            Some(q) => {
                let $modulus = UintModulus::new(q);
                $body
            }
        }
    };
}

const N: usize = 4096;
const T: u64 = 12289;
const Q: u64 = 1125899906826241;

fn values(len: usize, modulus: Option<u64>) -> Vec<u64> {
    (0..len)
        .map(|i| {
            let value = (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xd1b5_4a32_d192_ed03;
            modulus.map_or(value, |q| value % q)
        })
        .collect()
}

fn messages(len: usize, t: u64) -> Vec<u64> {
    let mut input = values(len, Some(t));
    input[..4].copy_from_slice(&[0, t.div_ceil(2) - 1, t.div_ceil(2), t - 1]);
    input
}

fn bench_rounded_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("rounded/encode_to/u64");
    for (name, t, q) in [
        ("exact_shift", 256, None),
        ("exact_multiply", 9, Some(45)),
        ("explicit_small", T, Some(Q)),
        ("native", T, None),
        ("explicit_large", T, Some(u64::MAX - 58)),
        ("large_plaintext", (1 << 40) + 87, Some(u64::MAX - 58)),
    ] {
        with_modulus!(q, modulus, {
            let codec = RoundedCodec::new(t, modulus);
            let input = messages(N, t);
            let mut output = vec![0; N];
            group.throughput(Throughput::Elements(N as u64));
            group.bench_function(BenchmarkId::new(format!("{name}/centered"), N), |b| {
                b.iter(|| {
                    black_box(&codec).encode_slice_to(
                        black_box(&input),
                        black_box(&mut output),
                        PlaintextEmbedding::Centered,
                    )
                })
            });
            if matches!(name, "explicit_small" | "native" | "explicit_large") {
                group.bench_function(BenchmarkId::new(format!("{name}/unsigned"), N), |b| {
                    b.iter(|| {
                        black_box(&codec).encode_slice_to(
                            black_box(&input),
                            black_box(&mut output),
                            PlaintextEmbedding::Unsigned,
                        )
                    })
                });
            }
            // One short/long pair tracks dispatch cost without repeating the
            // entire arithmetic matrix at every batch size.
            if name == "exact_shift" {
                group.throughput(Throughput::Elements(16));
                group.bench_function(BenchmarkId::new("exact_shift/centered", 16), |b| {
                    b.iter(|| {
                        black_box(&codec).encode_slice_to(
                            black_box(&input[..16]),
                            black_box(&mut output[..16]),
                            PlaintextEmbedding::Centered,
                        )
                    })
                });
            }
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    // Rounded and Scaled share decoding; one owner measures each kernel.
    let mut group = c.benchmark_group("decode/u64");
    for (name, t, q) in [
        ("shift", 256, None),
        ("divide", 9, Some(45)),
        ("native", T, None),
        ("narrow", T, Some(Q)),
        ("wide", T, Some(u64::MAX - 58)),
    ] {
        with_modulus!(q, modulus, {
            let codec = RoundedCodec::new(t, modulus);
            let mut input = values(N, q);
            input[..3].copy_from_slice(&[
                0,
                q.map_or(u64::MAX, |q| q - 1),
                codec.encode_value(t - 1, PlaintextEmbedding::Unsigned),
            ]);
            let mut output = vec![0u64; N];
            group.throughput(Throughput::Elements(N as u64));
            group.bench_function(BenchmarkId::new(format!("{name}/to"), N), |b| {
                b.iter(|| {
                    black_box(&codec).decode_slice_to(black_box(&input), black_box(&mut output))
                })
            });
            if name == "shift" {
                group.bench_function(BenchmarkId::new("shift/assign", N), |b| {
                    b.iter_batched_ref(
                        || input.clone(),
                        |phase| black_box(&codec).decode_slice_assign(black_box(phase)),
                        BatchSize::NumIterations(8),
                    )
                });
            }
        });
    }
    group.finish();
}

fn bench_u32(c: &mut Criterion) {
    let t = T as u32;
    let q = 536813569u32;
    let codec = RoundedCodec::new(t, BarrettModulus::new(q));
    let input: Vec<u32> = messages(N, u64::from(t))
        .into_iter()
        .map(|m| m as u32)
        .collect();
    let phases: Vec<u32> = values(N, Some(u64::from(q)))
        .into_iter()
        .map(|c| c as u32)
        .collect();
    let mut output = vec![0u32; N];
    let mut group = c.benchmark_group("explicit/u32");
    group.throughput(Throughput::Elements(N as u64));
    group.bench_function(BenchmarkId::new("rounded_encode_centered", N), |b| {
        b.iter(|| {
            black_box(&codec).encode_slice_to(
                black_box(&input),
                black_box(&mut output),
                PlaintextEmbedding::Centered,
            )
        })
    });
    group.bench_function(BenchmarkId::new("decode_to", N), |b| {
        b.iter(|| black_box(&codec).decode_slice_to(black_box(&phases), black_box(&mut output)))
    });
    group.finish();
}

fn bench_scaled_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaled/add_encode_centered/u64");
    group.throughput(Throughput::Elements(N as u64));
    for (name, t, q) in [
        ("native_shift", 256, None),
        ("explicit_multiply", T, Some(Q)),
    ] {
        with_modulus!(q, modulus, {
            let codec = ScaledCodec::new(t, modulus);
            let input = messages(N, t);
            let mut acc = values(N, q);
            group.bench_function(BenchmarkId::new(name, N), |b| {
                // Every iteration leaves a canonical accumulator for the next one.
                b.iter(|| {
                    black_box(&codec).add_encode_slice_assign(
                        black_box(&mut acc),
                        black_box(&input),
                        PlaintextEmbedding::Centered,
                    )
                })
            });
        });
    }
    group.finish();
}

fn bench_scalar(c: &mut Criterion) {
    let codec = RoundedCodec::new(256u64, NativeModulus::new());
    let phase = codec.encode_value(255u64, PlaintextEmbedding::Unsigned);
    let mut acc = u64::MAX;
    let mut group = c.benchmark_group("rounded/scalar/u64");
    group.bench_function("native_shift/decode", |b| {
        b.iter(|| black_box(&codec).decode_value(black_box(phase)))
    });
    group.bench_function("native_shift/add_encode", |b| {
        b.iter(|| {
            black_box(&codec).add_encode_value_assign(
                black_box(&mut acc),
                black_box(255u64),
                PlaintextEmbedding::Centered,
            )
        })
    });
    let ratio = RoundedCodec::new(T, NativeModulus::new());
    group.bench_function("native_ratio/encode", |b| {
        b.iter(|| black_box(&ratio).encode_value(black_box(T - 1), PlaintextEmbedding::Centered))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_rounded_encode,
    bench_decode,
    bench_u32,
    bench_scaled_add,
    bench_scalar
);
criterion_main!(benches);
