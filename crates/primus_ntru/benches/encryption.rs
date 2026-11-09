//! Ordinary encrypt_message_to and undecoded decrypt_phase_to; setup and allocations are excluded.
//! cargo bench -p primus_ntru --bench encryption --features ntt

use primus_encoding::PlaintextEmbedding;
use primus_shape::PolyLength;
use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_modulus::BarrettModulus;
use primus_ntru::{NtruParameters, NttNtruSecretKey, SecretKeyDistr};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

fn ntt(c: &mut Criterion, n: usize) {
    let modulus = BarrettModulus::new(1_125_899_906_826_241u64);
    let poly_length = PolyLength::new(n);
    let parameters =
        NtruParameters::new(poly_length, 16, modulus, SecretKeyDistr::SparseTernary, 3.2);
    let table = UintNttTable::new(poly_length, modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (_, key) =
        NttNtruSecretKey::generate_pair(parameters.encryption_parameters(), &table, &mut rng)
            .unwrap();
    let message = Polynomial::new((0..n).map(|i| i as u64 % 16).collect::<Vec<_>>());
    let input = key.encrypt_message(
        &message,
        &parameters,
        PlaintextEmbedding::Unsigned,
        &table,
        &mut rng,
    );
    let mut output = input.clone();
    let mut phase = Polynomial::<Vec<u64>>::zero(n);
    let mut group = c.benchmark_group(format!("ntru/encryption/ntt/n{n}"));
    group.throughput(Throughput::Elements(n as u64));
    group.bench_function("encrypt_to", |b| {
        b.iter(|| {
            key.encrypt_message_to(
                black_box(&message),
                &mut output,
                &parameters,
                PlaintextEmbedding::Unsigned,
                &table,
                &mut rng,
            );
            black_box(output.as_ref());
        })
    });
    group.bench_function("phase_to", |b| {
        b.iter(|| {
            key.decrypt_phase_to(black_box(&input), &mut phase, modulus, &table);
            black_box(phase.as_ref());
        })
    });
    group.finish();
}

fn benchmarks(c: &mut Criterion) {
    for n in [1024, 4096, 8192] {
        ntt(c, n);
    }
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
