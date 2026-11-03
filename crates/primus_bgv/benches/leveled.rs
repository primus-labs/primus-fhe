//! One complete fresh leveled slot request; keys/setup/allocations stay outside timing.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_bgv::{
    BgvAutomorphism, BgvClient, BgvContext, BgvKeySwitcher, BgvModulusSwitch, BgvMultiplication,
    BgvParameters,
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_encoding::BatchingEncoder;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

fn leveled(c: &mut Criterion) {
    const N: usize = 1024;
    const SLOTS: usize = 256;
    const ACTIVE: usize = 113;
    const P: u64 = 12_289;
    // Each verified prime is 1 modulo both p and 2N; Q has 150 bits.
    let moduli = [
        1_125_899_426_789_377,
        1_125_899_326_117_889,
        1_125_898_722_088_961,
    ]
    .map(BarrettModulus::new);
    let context = BgvContext::try_with_levels(
        BgvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &moduli,
            SecretKeyDistr::SparseTernary,
            0.849,
        )
        .unwrap(),
        3,
    )
    .unwrap();
    let batching =
        BatchingEncoder::try_new(PolyLength::new(SLOTS), context.parameters().plain_modulus())
            .unwrap();
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let mut rng = StdRng::seed_from_u64(0x10b6_be0c);
    let alice = BgvClient::generate(&context, &mut rng);
    let mut bob = BgvClient::generate(&context, &mut rng);
    let public_key = alice.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key).unwrap();
    let relin_key = alice.relinearization_key(0, config, &mut rng).unwrap();
    let rotate_key = alice
        .row_rotation_key(1, &batching, 1, config, &mut rng)
        .unwrap();
    let switch_key = bob.key_switching_key(&alice, 1, config, &mut rng).unwrap();
    let mut multiplication = BgvMultiplication::try_new(&context, &relin_key).unwrap();
    let mut rotate = BgvAutomorphism::try_new(&context, &rotate_key).unwrap();
    let mut switch = BgvKeySwitcher::try_new(&context, &switch_key).unwrap();
    let mut drop_first = BgvModulusSwitch::new(&context, 0);
    let mut drop_second = BgvModulusSwitch::new(&context, 1);
    let values: Vec<_> = (0..ACTIVE).map(|i| (7 * i as u64 + 1) % P).collect();
    let factors: Vec<_> = (0..SLOTS).map(|i| 1 + i as u64 % 3).collect();
    let mut small = vec![0; SLOTS];
    let mut a = context.new_plaintext();
    let mut b = context.new_plaintext();
    let mut encrypted_a = context.new_ciphertext(0);
    let mut encrypted_b = context.new_ciphertext(0);
    let mut linear = context.new_ciphertext(0);
    let mut lower = context.new_ciphertext(1);
    let mut rotated = context.new_ciphertext(1);
    let mut switched = context.new_ciphertext(1);
    let mut lowest = context.new_ciphertext(2);
    let mut recovered = context.new_plaintext();
    let mut slots = vec![0; SLOTS];
    let mut scratch = vec![0; SLOTS];

    let mut group = c.benchmark_group("bgv_leveled_slots");
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
            bob.decrypt_to(&lowest, 2, &mut recovered);
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
