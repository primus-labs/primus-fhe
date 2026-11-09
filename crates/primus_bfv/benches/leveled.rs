//! Run: cargo bench -p primus_bfv --bench leveled
//! Smoke: cargo bench -p primus_bfv --bench leveled -- --test
//!
//! Each sample performs one named workload. Contexts, codecs, keys, NTT tables,
//! outputs and scratch are prepared outside measurement. The full request
//! includes encryption, plaintext addition/multiplication, both rounded level
//! drops and coefficient recovery. Diagnostic parameters are not a security preset.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_bfv::evaluation::{BfvEvaluator, BfvModulusSwitch};
use primus_bfv::{BfvClient, BfvContext, BfvParameters, PlaintextEmbedding};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn expected_product(lhs: &[u64], rhs: &[u64], modulus: u64) -> Polynomial<Vec<u64>> {
    let n = lhs.len();
    let mut result = vec![0_i128; n];
    for (i, &a) in lhs.iter().enumerate() {
        for (j, &b) in rhs.iter().enumerate() {
            let product = i128::from(a) * i128::from(b);
            if i + j < n {
                result[i + j] += product;
            } else {
                result[i + j - n] -= product;
            }
        }
    }
    Polynomial(
        result
            .into_iter()
            .map(|value| value.rem_euclid(i128::from(modulus)) as u64)
            .collect(),
    )
}

fn bench_leveled(c: &mut Criterion) {
    const N: usize = 1024;
    const T: u64 = 12_289;
    let parameters = BfvParameters::try_with_decoder_modulus(
        PolyLength::new(N),
        BarrettModulus::new(T),
        BarrettModulus::new(2_199_023_190_017),
        &[
            1_125_899_906_826_241,
            1_125_899_906_629_633,
            1_125_899_906_031_617,
        ]
        .map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::Gaussian {
            standard_deviation: 3.2,
        },
    )
    .unwrap();
    let context = BfvContext::try_with_levels(parameters, 3).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4246_565f_4245_4e43);
    let mut client = BfvClient::generate(&context, &mut rng);
    let mut evaluator = BfvEvaluator::new(&context, 0);
    let mut switch_zero = BfvModulusSwitch::new(&context, 0);
    let mut switch_one = BfvModulusSwitch::new(&context, 1);
    let message = Polynomial((0..N).map(|i| (i % 4) as u64).collect::<Vec<_>>());
    let addend = Polynomial((0..N).map(|i| [1, T - 1, 0][i % 3]).collect::<Vec<_>>());
    let multiplier = Polynomial((0..N).map(|i| [T - 1, 1][i % 2]).collect::<Vec<_>>());
    let sum = Polynomial(
        message
            .as_ref()
            .iter()
            .zip(addend.as_ref())
            .map(|(&a, &b)| (a + b) % T)
            .collect::<Vec<_>>(),
    );
    let expected = expected_product(sum.as_ref(), multiplier.as_ref(), T);
    let mut input = context.new_ciphertext(0);
    let mut linear = context.new_ciphertext(0);
    let mut product = context.new_ciphertext(0);
    let mut level_one = context.new_ciphertext(1);
    let mut level_two = context.new_ciphertext(2);
    let mut decoded = Polynomial::<Vec<u64>>::zero(N);

    // Validate the complete measured request with an independent schoolbook
    // oracle. Individual benchmark inputs below remain fixed throughout timing.
    client.encrypt_centered_to(&message, &mut input, &mut rng);
    evaluator.add_plain_to(&input, &addend, &mut linear, PlaintextEmbedding::Centered);
    evaluator.mul_plain_to(
        &linear,
        &multiplier,
        &mut product,
        PlaintextEmbedding::Centered,
    );
    switch_zero.switch_to(&product, &mut level_one);
    switch_one.switch_to(&level_one, &mut level_two);
    client.decrypt_at_level_to(&level_two, 2, &mut decoded);
    assert_eq!(decoded, expected);

    let mut group = c.benchmark_group("leveled/N1024/u64/rank1/Q3x50/t12289");
    group.bench_function("dense_plain_mul_to", |b| {
        b.iter(|| {
            evaluator.mul_plain_to(
                black_box(&linear),
                black_box(&multiplier),
                black_box(&mut product),
                PlaintextEmbedding::Centered,
            );
        });
    });
    group.bench_function("rounded_drop_3_to_2", |b| {
        b.iter(|| {
            switch_zero.switch_to(black_box(&product), black_box(&mut level_one));
        });
    });
    group.bench_function("private_encrypt_linear_mul_two_drops_decrypt_to", |b| {
        b.iter(|| {
            client.encrypt_centered_to(black_box(&message), &mut input, &mut rng);
            evaluator.add_plain_to(&input, &addend, &mut linear, PlaintextEmbedding::Centered);
            evaluator.mul_plain_to(
                &linear,
                &multiplier,
                &mut product,
                PlaintextEmbedding::Centered,
            );
            switch_zero.switch_to(&product, &mut level_one);
            switch_one.switch_to(&level_one, &mut level_two);
            client.decrypt_at_level_to(&level_two, 2, black_box(&mut decoded));
        });
    });
    group.finish();
}

criterion_group!(benches, bench_leveled);
criterion_main!(benches);
