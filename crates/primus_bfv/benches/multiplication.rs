//! One complete fresh leveled slot request; keys/setup/allocations stay outside timing.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_bfv::evaluation::{
    BfvAutomorphism, BfvKeySwitcher, BfvModulusSwitch, BfvMultiplication, BfvMultiplicationBackend,
};
use primus_bfv::keys::BfvEvaluationKeyConfig;
use primus_bfv::{BfvClient, BfvContext, BfvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_encoding::BatchingEncoder;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

fn leveled(c: &mut Criterion) {
    for backend in [
        BfvMultiplicationBackend::Exact,
        BfvMultiplicationBackend::HpsPOverQ,
    ] {
        for hybrid_keys in [false, true] {
            leveled_backend(c, backend, hybrid_keys);
        }
    }
}

fn leveled_backend(c: &mut Criterion, backend: BfvMultiplicationBackend, hybrid_keys: bool) {
    const N: usize = 1024;
    const SLOTS: usize = 256;
    const ACTIVE: usize = 113;
    const P: u64 = 12_289;
    // Q has 150 bits; BFV does not require q_i = 1 mod t.
    let moduli = [
        1_125_899_906_826_241,
        1_125_899_906_629_633,
        1_125_899_906_031_617,
    ]
    .map(BarrettModulus::new);
    let context = BfvContext::try_with_levels(
        BfvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &moduli,
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::Gaussian {
                standard_deviation: 0.849,
            },
        )
        .unwrap(),
        3,
    )
    .unwrap();
    let batching =
        BatchingEncoder::try_new(PolyLength::new(SLOTS), BarrettModulus::new(P)).unwrap();
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let key_config: BfvEvaluationKeyConfig = if hybrid_keys {
        context
            .hybrid_key_parameters(0, moduli.len(), &[1_152_921_504_606_584_833])
            .unwrap()
            .into()
    } else {
        config.into()
    };
    let lower_key_config: BfvEvaluationKeyConfig = if hybrid_keys {
        context
            .hybrid_key_parameters(1, moduli.len(), &[1_152_921_504_606_584_833])
            .unwrap()
            .into()
    } else {
        config.into()
    };
    let mut rng = StdRng::seed_from_u64(0x10b6_be0c);
    let alice = BfvClient::generate(&context, &mut rng);
    let mut bob = BfvClient::generate(&context, &mut rng);
    let public_key = alice.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key).unwrap();
    let relin_key = alice.relinearization_key(0, key_config, &mut rng).unwrap();
    let rotate_key = alice
        .row_rotation_key(1, &batching, 1, lower_key_config.clone(), &mut rng)
        .unwrap();
    let switch_key = bob
        .key_switching_key(&alice, 1, lower_key_config, &mut rng)
        .unwrap();
    let mut rotate = BfvAutomorphism::try_new(&context, &rotate_key).unwrap();
    let mut switch = BfvKeySwitcher::try_new(&context, &switch_key).unwrap();
    // Keep this explicit P for equivalent-workload historical comparisons.
    let mut multiplication = if backend == BfvMultiplicationBackend::Exact {
        BfvMultiplication::try_with_backend_and_auxiliary_moduli(
            &context,
            &relin_key,
            backend,
            &[
                1_152_921_504_606_584_833,
                1_152_921_504_598_720_513,
                1_152_921_504_592_429_057,
            ],
        )
        .unwrap()
    } else {
        BfvMultiplication::try_with_backend(&context, &relin_key, backend).unwrap()
    };
    let mut drop_first = BfvModulusSwitch::new(&context, 0);
    let mut drop_second = BfvModulusSwitch::new(&context, 1);
    let values: Vec<_> = (0..ACTIVE).map(|i| (7 * i as u64 + 1) % P).collect();
    let factors: Vec<_> = (0..SLOTS).map(|i| 1 + i as u64 % 3).collect();
    let mut small = vec![0; SLOTS];
    let mut a = Polynomial::<Vec<u64>>::zero(N);
    let mut b = Polynomial::<Vec<u64>>::zero(N);
    let mut encrypted_a = context.new_ciphertext(0);
    let mut encrypted_b = context.new_ciphertext(0);
    let mut linear = context.new_ciphertext(0);
    let mut lower = context.new_ciphertext(1);
    let mut rotated = context.new_ciphertext(1);
    let mut switched = context.new_ciphertext(1);
    let mut lowest = context.new_ciphertext(2);
    let mut recovered = Polynomial::<Vec<u64>>::zero(N);
    let mut slots = vec![0; SLOTS];
    let mut scratch = vec![0; SLOTS];

    let mut group = c.benchmark_group(format!(
        "bfv_leveled_slots/{backend:?}/{}",
        if hybrid_keys { "Hybrid" } else { "Radix" }
    ));
    group.throughput(Throughput::Elements(1));
    {
        let mut request = || {
            batching.encode_to(black_box(&values), &mut small);
            batching.embed_to(&small, a.as_mut());
            batching.encode_to(black_box(&factors), &mut small);
            batching.embed_to(&small, b.as_mut());
            encryptor.encrypt_centered_to(&a, &mut encrypted_a, &mut rng);
            encryptor.encrypt_centered_to(&b, &mut encrypted_b, &mut rng);
            multiplication.multiply_to(&encrypted_a, &encrypted_b, &mut linear);
            multiplication.square_assign(&mut linear);
            drop_first.switch_to(&linear, &mut lower);
            rotate.apply_to(&lower, &mut rotated);
            switch.switch_to(&rotated, &mut switched);
            drop_second.switch_to(&switched, &mut lowest);
            bob.decrypt_at_level_to(&lowest, 2, &mut recovered);
            batching.extract_to(recovered.as_ref(), &mut small);
            batching.decode_to(&small, &mut slots, &mut scratch);
            black_box(&slots);
        };
        group.bench_function(
            "encode_two_public_mul_square_relin_rotate_switch_drop_recover_n1024_n256_q150",
            |b| b.iter(&mut request),
        );
    }
    group.finish();
    let original: Vec<_> = (0..SLOTS)
        .map(|i| {
            if i < ACTIVE {
                let product = values[i] * factors[i] % P;
                product * product % P
            } else {
                0
            }
        })
        .collect();
    let half = SLOTS / 2;
    let expected: Vec<_> = (0..SLOTS)
        .map(|i| original[(i / half) * half + (i % half + 1) % half])
        .collect();
    assert_eq!(slots, expected);
    assert!(
        recovered
            .as_ref()
            .iter()
            .enumerate()
            .all(|(i, &value)| i % (N / SLOTS) == 0 || value == 0)
    );
}

criterion_group!(benches, leveled);
criterion_main!(benches);
