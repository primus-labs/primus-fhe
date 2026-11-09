//! BFV coefficient operations with reusable codecs, output and conversion scratch.
//! Throughput counts plaintext coefficients; case names include the RNS limb count.
//! Decode restores destructive input outside timing in fixed batches of eight.
//!
//! Compare SIMD with the same toolchain:
//! cargo +nightly bench -p primus_encoding --bench bfv_rns --features rns
//! cargo +nightly bench -p primus_encoding --bench bfv_rns --features rns,simd

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_encoding::{BfvRnsCodec, PlaintextEmbedding};
use primus_modulus::BarrettModulus;
use primus_poly::{CrtPolynomial, Polynomial};
use primus_rns::RNSBase;
use std::hint::black_box;

fn bench_bfv(c: &mut Criterion) {
    const N: usize = 4096;
    let moduli = [1125899906826241u64, 1125899906629633].map(BarrettModulus::new);
    let input = Polynomial::new((0..N).map(|i| (i as u64 * 17) % 12289).collect::<Vec<_>>());
    for k in [1, 2] {
        let codec = BfvRnsCodec::new(
            BarrettModulus::new(12289),
            RNSBase::new(&moduli[..k]).unwrap(),
            BarrettModulus::new(2305843009213554689),
        );
        let mut encoded = CrtPolynomial::<Vec<u64>>::zero(N * k);
        let mut output = Polynomial::<Vec<u64>>::zero(N);
        let mut scratch = vec![0; codec.decode_scratch_len(N)];
        let mut group = c.benchmark_group(format!("bfv_rns/limbs_{k}"));
        group.throughput(Throughput::Elements(N as u64));
        if k == 2 {
            for (name, embedding) in [
                ("add_encode_unsigned", PlaintextEmbedding::Unsigned),
                ("add_encode_centered", PlaintextEmbedding::Centered),
            ] {
                group.bench_function(BenchmarkId::new(name, N), |b| {
                    // Modular accumulation preserves the input range across iterations.
                    b.iter(|| {
                        black_box(&codec).add_encode_coeffs_assign(
                            black_box(&input),
                            black_box(&mut encoded),
                            embedding,
                        )
                    })
                });
            }
        }
        codec.encode_coeffs_to(&input, &mut encoded, PlaintextEmbedding::Centered);
        group.bench_function(BenchmarkId::new("decode", N), |b| {
            b.iter_batched_ref(
                || encoded.clone(),
                |phase| {
                    black_box(&codec).decode_coeffs_to(
                        black_box(phase),
                        black_box(&mut output),
                        black_box(&mut scratch),
                    )
                },
                BatchSize::NumIterations(8),
            )
        });
        group.finish();
    }
}

criterion_group!(benches, bench_bfv);
criterion_main!(benches);
