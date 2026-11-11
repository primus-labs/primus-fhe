//! Coefficient throughput and scalar-call cost with reusable codecs and buffers.
//! Inputs sample across the plaintext/ciphertext ranges, including the centered
//! boundary. In-place decoding restores its input outside timing in fixed batches.

use std::hint::black_box;

use criterion::{
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
    measurement::WallTime,
};
use primus_encoding::PlaintextEmbedding::{Centered, Unsigned};
use primus_encoding::{PlaintextEmbedding, RoundedCodec, ScaledCodec};
use primus_modulus::{BarrettModulus, NativeModulus, UintModulus};
use primus_reduce::{Modulus, ReduceAdd};

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
    let native = NativeModulus::new();
    let wide = UintModulus::new(u64::MAX - 58);
    let mut group = c.benchmark_group("rounded/encode_to/u64");
    // A short exact-shift case tracks dispatch cost. The native ratio case
    // provides a matched comparison of the two plaintext embeddings.
    rounded_encode_case(
        &mut group,
        "exact_shift",
        RoundedCodec::new(256, native),
        &[(N, Centered), (16, Centered)],
    );
    rounded_encode_case(
        &mut group,
        "exact_multiply",
        RoundedCodec::new(9, BarrettModulus::new(45)),
        &[(N, Centered)],
    );
    rounded_encode_case(
        &mut group,
        "explicit_small",
        RoundedCodec::new(T, BarrettModulus::new(Q)),
        &[(N, Centered)],
    );
    rounded_encode_case(
        &mut group,
        "native",
        RoundedCodec::new(T, native),
        &[(N, Centered), (N, Unsigned)],
    );
    for (name, t) in [("explicit_large", T), ("large_plaintext", (1 << 40) + 87)] {
        rounded_encode_case(
            &mut group,
            name,
            RoundedCodec::new(t, wide),
            &[(N, Centered)],
        );
    }
    group.finish();
}

fn rounded_encode_case<M: Modulus<ValueT = u64> + ReduceAdd<u64, Output = u64>>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    codec: RoundedCodec<u64, M>,
    cases: &[(usize, PlaintextEmbedding)],
) {
    let input = messages(N, codec.plaintext_modulus());
    let mut output = vec![0; N];
    for &(len, embedding) in cases {
        let input = &input[..len];
        let output = &mut output[..len];
        let label = match embedding {
            Centered => "centered",
            Unsigned => "unsigned",
        };
        group.throughput(Throughput::Elements(len as u64));
        group.bench_function(BenchmarkId::new(format!("{name}/{label}"), len), |b| {
            b.iter(|| {
                black_box(&codec).encode_slice_to(
                    black_box(input),
                    black_box(&mut *output),
                    embedding,
                )
            });
        });
    }
}

fn bench_decode(c: &mut Criterion) {
    // Rounded and Scaled share decoding; one owner measures each kernel.
    let mut group = c.benchmark_group("decode/u64");
    group.throughput(Throughput::Elements(N as u64));
    let native = NativeModulus::new();
    decode_case(&mut group, "shift", RoundedCodec::new(256, native));
    decode_case(
        &mut group,
        "divide",
        RoundedCodec::new(9, BarrettModulus::new(45)),
    );
    decode_case(&mut group, "native", RoundedCodec::new(T, native));
    decode_case(
        &mut group,
        "narrow",
        RoundedCodec::new(T, BarrettModulus::new(Q)),
    );
    decode_case(
        &mut group,
        "wide",
        RoundedCodec::new(T, UintModulus::new(u64::MAX - 58)),
    );
    group.finish();
}

fn decode_case<M: Modulus<ValueT = u64> + ReduceAdd<u64, Output = u64>>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    codec: RoundedCodec<u64, M>,
) {
    let modulus = codec.ciphertext_modulus();
    let mut input = values(N, modulus.explicit_value());
    input[..3].copy_from_slice(&[
        0,
        modulus.minus_one(),
        codec.encode_value(codec.plaintext_modulus() - 1, Unsigned),
    ]);
    let mut output = vec![0u64; N];
    group.bench_function(BenchmarkId::new(format!("{name}/to"), N), |b| {
        b.iter(|| black_box(&codec).decode_slice_to(black_box(&input), black_box(&mut output)))
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
    scaled_add_case(
        &mut group,
        "native_shift",
        ScaledCodec::new(256, NativeModulus::new()),
    );
    scaled_add_case(
        &mut group,
        "explicit_multiply",
        ScaledCodec::new(T, BarrettModulus::new(Q)),
    );
    group.finish();
}

fn scaled_add_case<M: Modulus<ValueT = u64> + ReduceAdd<u64, Output = u64>>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    codec: ScaledCodec<u64, M>,
) {
    let input = messages(N, codec.plaintext_modulus());
    let mut acc = values(N, codec.ciphertext_modulus().explicit_value());
    group.bench_function(BenchmarkId::new(name, N), |b| {
        // Every iteration leaves a canonical accumulator for the next one.
        b.iter(|| {
            black_box(&codec).add_encode_slice_assign(
                black_box(&mut acc),
                black_box(&input),
                Centered,
            )
        })
    });
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
