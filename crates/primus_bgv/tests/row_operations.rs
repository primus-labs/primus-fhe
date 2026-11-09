#![cfg(feature = "batching")]
//! Signed row operations bind an encoder's geometry without changing full-ring secrets.

use primus_bgv::evaluation::{BgvAutomorphism, BgvModulusSwitch};
use primus_bgv::keys::BgvEvaluationKeyError;
use primus_bgv::{BgvClient, BgvContext, BgvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_encoding::BatchingEncoder;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

const P: u64 = 193;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];

fn context(n: usize) -> BgvContext {
    BgvContext::try_with_levels(
        BgvParameters::try_coefficients(
            PolyLength::new(n),
            BarrettModulus::new(P),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
        Q.len(),
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
fn signed_rotations_and_swaps_preserve_full_ring_and_subring_slots_at_each_level() {
    const CAPACITY: usize = 32;
    let values = (1..=CAPACITY as u64).collect::<Vec<_>>();
    for n in [CAPACITY, 2 * CAPACITY] {
        let context = context(n);
        let batching = if n == CAPACITY {
            context.batching_encoder().unwrap()
        } else {
            assert!(context.batching_encoder().is_err());
            BatchingEncoder::try_new(
                PolyLength::new(CAPACITY),
                context.parameters().plain_modulus(),
            )
            .unwrap()
        };
        let encoded = batching.encode(&values);
        let mut plaintext = context.new_plaintext();
        batching.embed_to(&encoded, plaintext.as_mut());
        let mut rng = StdRng::seed_from_u64(0x13b6_5107 + n as u64);
        let mut client = BgvClient::generate(&context, &mut rng);
        for level in 0..context.level_count() {
            let mut input = client.encrypt_centered(&plaintext, &mut rng);
            for from in 0..level {
                let mut lower = context.new_ciphertext(from + 1);
                BgvModulusSwitch::new(&context, from).switch_to(&input, &mut lower);
                input = lower;
            }
            let mut output = context.new_ciphertext(level);
            let half = CAPACITY / 2;
            for steps in [
                -(half as isize + 1),
                -1,
                0,
                1,
                half as isize + 1,
                isize::MIN,
                isize::MAX,
            ] {
                let key = client
                    .row_rotation_key(level, &batching, steps, config(), &mut rng)
                    .unwrap();
                BgvAutomorphism::try_new(&context, &key)
                    .unwrap()
                    .apply_to(&input, &mut output);
                let recovered = client.decrypt_at_level(&output, level);
                let mut small = vec![0; CAPACITY];
                batching.extract_to(recovered.as_ref(), &mut small);
                let actual = batching.decode(&small);
                let offset = steps.rem_euclid(half as isize) as usize;
                let expected = (0..CAPACITY)
                    .map(|i| values[i / half * half + (i % half + offset) % half])
                    .collect::<Vec<_>>();
                assert_eq!(actual, expected, "N={n}, level={level}, steps={steps}");
            }
            let key = client
                .row_swap_key(level, &batching, config(), &mut rng)
                .unwrap();
            BgvAutomorphism::try_new(&context, &key)
                .unwrap()
                .apply_to(&input, &mut output);
            let recovered = client.decrypt_at_level(&output, level);
            let mut small = vec![0; CAPACITY];
            batching.extract_to(recovered.as_ref(), &mut small);
            let actual = batching.decode(&small);
            let expected = (0..CAPACITY)
                .map(|i| values[(i + half) % CAPACITY])
                .collect::<Vec<_>>();
            assert_eq!(actual, expected);
        }
    }
}

#[test]
fn row_keys_reject_wrong_plaintext_modulus_and_excess_capacity_before_sampling() {
    let context = BgvContext::try_new(
        BgvParameters::try_coefficients(
            PolyLength::new(32),
            BarrettModulus::new(12_289),
            &[1_125_899_426_789_377, 1_125_899_326_117_889].map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
    )
    .unwrap();
    let mut setup_rng = StdRng::seed_from_u64(0x13b6_bad0);
    let client = BgvClient::generate(&context, &mut setup_rng);
    let wrong_p = BatchingEncoder::try_new(PolyLength::new(32), BarrettModulus::new(P)).unwrap();
    let excessive_capacity =
        BatchingEncoder::try_new(PolyLength::new(64), BarrettModulus::new(12_289)).unwrap();
    for (encoder, capacity_error) in [(&wrong_p, false), (&excessive_capacity, true)] {
        for rotation in [false, true] {
            let mut rng = StdRng::seed_from_u64(73);
            let mut expected = StdRng::seed_from_u64(73);
            let result = if rotation {
                client.row_rotation_key(0, encoder, -1, config(), &mut rng)
            } else {
                client.row_swap_key(0, encoder, config(), &mut rng)
            };
            if capacity_error {
                assert!(matches!(
                    result,
                    Err(BgvEvaluationKeyError::SlotCapacity {
                        maximum: 32,
                        actual: 64
                    })
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(BgvEvaluationKeyError::PlainModulus {
                        expected: 12_289,
                        actual: P
                    })
                ));
            }
            assert_eq!(rng.next_u64(), expected.next_u64());
        }
    }
}
