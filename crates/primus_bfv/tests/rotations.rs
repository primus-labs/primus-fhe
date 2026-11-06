#![cfg(feature = "batching")]

use primus_bfv::{
    BfvAutomorphism, BfvClient, BfvContext, BfvEvaluationKeyError, BfvModulusSwitch, BfvParameters,
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_encoding::BatchingEncoder;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

fn context(n: usize, p: u64) -> BfvContext {
    BfvContext::try_with_levels(
        BfvParameters::try_coefficients(
            PolyLength::new(n),
            BarrettModulus::new(p),
            &[1_125_899_906_826_241, 1_125_899_906_629_633].map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            0.849,
        )
        .unwrap(),
        2,
    )
    .unwrap()
}

fn config() -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    }
}

#[test]
fn signed_row_keys_preserve_full_ring_and_subring_slot_maps_at_each_level() {
    for (n, capacity) in [(32, 32), (64, 32)] {
        let context = context(n, 257);
        let encoder = if n == capacity {
            context.batching_encoder().unwrap()
        } else {
            BatchingEncoder::try_new(PolyLength::new(capacity), BarrettModulus::new(257)).unwrap()
        };
        let mut rng = StdRng::seed_from_u64(0x13bf_5070 + n as u64);
        let mut client = BfvClient::generate(&context, &mut rng);
        let values: Vec<_> = (0..capacity).map(|i| (3 * i + 1) as u64).collect();
        let mut small = vec![0; capacity];
        encoder.encode_to(&values, &mut small);
        let mut plaintext = context.new_plaintext();
        encoder.embed_to(&small, plaintext.as_mut());
        let mut input = client.encrypt_centered(&plaintext, &mut rng);
        for level in 0..context.level_count() {
            let mut output = context.new_ciphertext(level);
            let half = capacity / 2;
            for steps in [
                -1,
                1,
                half as isize + 1,
                -(half as isize) - 1,
                isize::MIN,
                isize::MAX,
            ] {
                let key = client
                    .row_rotation_key(level, &encoder, steps, config(), &mut rng)
                    .unwrap();
                BfvAutomorphism::try_new(&context, &key)
                    .unwrap()
                    .apply_to(&input, &mut output);
                let recovered = client.decrypt_at_level(&output, level);
                encoder.extract_to(recovered.as_ref(), &mut small);
                let actual = encoder.decode(&small);
                let shift = steps.rem_euclid(half as isize) as usize;
                let expected: Vec<_> = (0..capacity)
                    .map(|i| values[(i / half) * half + (i % half + shift) % half])
                    .collect();
                assert_eq!(
                    actual, expected,
                    "N={n}, n={capacity}, level={level}, steps={steps}"
                );
            }
            let key = client
                .row_swap_key(level, &encoder, config(), &mut rng)
                .unwrap();
            BfvAutomorphism::try_new(&context, &key)
                .unwrap()
                .apply_to(&input, &mut output);
            encoder.extract_to(client.decrypt_at_level(&output, level).as_ref(), &mut small);
            let expected: Vec<_> = (0..capacity)
                .map(|i| values[(i + half) % capacity])
                .collect();
            assert_eq!(encoder.decode(&small), expected);
            if level == 0 {
                let mut next = context.new_ciphertext(1);
                BfvModulusSwitch::new(&context, 0).switch_to(&input, &mut next);
                input = next;
            }
        }
    }
}

#[test]
fn encoder_mismatches_reject_before_sampling_and_subring_remains_explicit() {
    let context = context(32, 257);
    let client = BfvClient::generate(&context, &mut StdRng::seed_from_u64(0x13bf_50ff));
    for encoder in [
        BatchingEncoder::try_new(PolyLength::new(32), BarrettModulus::new(193)).unwrap(),
        BatchingEncoder::try_new(PolyLength::new(64), BarrettModulus::new(257)).unwrap(),
    ] {
        for swap in [false, true] {
            let mut rng = StdRng::seed_from_u64(0x13bf_50fd);
            let mut untouched_rng = StdRng::seed_from_u64(0x13bf_50fd);
            let result = if swap {
                client.row_swap_key(0, &encoder, config(), &mut rng)
            } else {
                client.row_rotation_key(0, &encoder, -1, config(), &mut rng)
            };
            if encoder.plain_modulus() != 257 {
                assert!(matches!(
                    result,
                    Err(BfvEvaluationKeyError::PlainModulus {
                        expected: 257,
                        actual: 193
                    })
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(BfvEvaluationKeyError::SlotCapacity {
                        maximum: 32,
                        actual: 64
                    })
                ));
            }
            assert_eq!(rng.next_u64(), untouched_rng.next_u64());
        }
    }
    // p supports n=32, but not full ciphertext N=64. Coefficient use and the
    // existing explicit subring encoder must not inherit the stronger condition.
    let context = self::context(64, 193);
    assert!(context.batching_encoder().is_err());
    let subring = BatchingEncoder::try_new(PolyLength::new(32), BarrettModulus::new(193)).unwrap();
    let mut rng = StdRng::seed_from_u64(0x13bf_50fe);
    let client = BfvClient::generate(&context, &mut rng);
    assert!(
        client
            .row_rotation_key(0, &subring, 1, config(), &mut rng)
            .is_ok()
    );
}
