//! Run: cargo bench -p primus_bfv --bench key_switching
//! Smoke: cargo bench -p primus_bfv --bench key_switching -- --test
//!
//! One native BFV switch per iteration; key generation, validation and reusable
//! scratch/output preparation stay outside timing. Diagnostic parameters only.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_bfv::evaluation::BfvKeySwitcher;
use primus_bfv::keys::BfvEvaluationKeyConfig;
use primus_bfv::{BfvClient, BfvContext, BfvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn bench_key_switching(c: &mut Criterion) {
    const N: usize = 1024;
    const T: u64 = 2;
    const Q: [u64; 2] = [1_125_899_906_826_241, 1_125_899_906_629_633];
    const P: [u64; 2] = [1_125_899_906_031_617, 1_125_899_904_679_937];
    let parameters = BfvParameters::try_with_decoder_modulus(
        PolyLength::new(N),
        BarrettModulus::new(T),
        BarrettModulus::new(2_305_843_009_213_554_689),
        &Q.map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::Gaussian {
            standard_deviation: 3.2,
        },
    )
    .unwrap();
    let context = BfvContext::try_new(parameters).unwrap();
    let mut rng = StdRng::seed_from_u64(0xdec0_005e);
    let alice = BfvClient::generate(&context, &mut rng);
    let mut bob = BfvClient::generate(&context, &mut rng);
    let mut message = context.new_plaintext();
    for (index, coefficient) in message.as_mut().iter_mut().enumerate() {
        *coefficient = (index as u64 + index as u64 / 7) % T;
    }
    let input = alice.encrypt(&message, &mut rng);
    let mut output = context.new_ciphertext(0);
    let mut recovered = context.new_plaintext();
    let cases: [(&str, BfvEvaluationKeyConfig); 3] = [
        (
            "Radix20",
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(20),
                level_count: None,
            }
            .into(),
        ),
        (
            "Hybrid-grouped",
            context.hybrid_key_parameters(0, 1, &P).unwrap().into(),
        ),
        (
            "Hybrid-singleton",
            context.hybrid_key_parameters(0, 2, &P).unwrap().into(),
        ),
    ];

    let mut group = c.benchmark_group("bfv_key_switching/N1024/Q2x50");
    group.sample_size(10);
    group.throughput(Throughput::Elements(N as u64));
    for (label, config) in cases {
        let key = bob.key_switching_key(&alice, 0, config, &mut rng).unwrap();
        let mut switcher = BfvKeySwitcher::try_new(&context, &key).unwrap();
        switcher.switch_to(&input, &mut output);
        bob.decrypt_at_level_to(&output, 0, &mut recovered);
        assert_eq!(recovered, message);

        group.bench_function(label, |b| {
            b.iter(|| {
                switcher.switch_to(black_box(&input), black_box(&mut output));
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_key_switching);
criterion_main!(benches);
