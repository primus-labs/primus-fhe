//! Public evaluation-key binding and pre-write rejection boundaries.

use dashu_int::IBig;
use primus_bfv::advanced::BfvQuadraticCiphertext;
use primus_bfv::evaluation::{BfvAutomorphism, BfvKeySwitcher, BfvRelinearizer};
use primus_bfv::keys::BfvEvaluationKeyError;
use primus_bfv::{BfvCiphertext, BfvClient, BfvContext, BfvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
const P: u64 = 257;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];

fn make_context(p: u64, moduli: &[u64], n: usize) -> BfvContext {
    BfvContext::try_with_levels(
        BfvParameters::try_coefficients(
            PolyLength::new(n),
            BarrettModulus::new(p),
            &moduli
                .iter()
                .copied()
                .map(BarrettModulus::new)
                .collect::<Vec<_>>(),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
        moduli.len(),
    )
    .unwrap()
}

fn client<'a>(context: &'a BfvContext, secret: &[i64]) -> BfvClient<'a> {
    let coefficient_key = GlweSecretKey::new(
        secret.to_vec(),
        context.parameters().size().glwe_size(),
        SecretKeyDistr::SparseTernary,
    );
    BfvClient::try_from_secret_key(
        context,
        DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, context.table()),
    )
    .unwrap()
}

fn total_modulus(count: usize) -> IBig {
    Q[..count]
        .iter()
        .fold(IBig::ONE, |value, &q| value * IBig::from(q))
}

fn config(count: usize, truncated: bool) -> DecompositionConfig {
    let width = format!("{:b}", total_modulus(count)).len();
    assert_eq!(width % 10, 0);
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(10),
        level_count: truncated.then(|| DecompositionLevelCount::new(width / 10 - 1)),
    }
}

#[test]
fn evaluation_keys_reject_numeric_mismatches_and_bad_storage_before_writes() {
    let context = make_context(P, &Q, N);
    let secret: Vec<i64> = (0..N).map(|i| [-1, 0, 1][i % 3]).collect();
    let client = client(&context, &secret);
    let mut rng = StdRng::seed_from_u64(0x10b6_bad0);
    let config = config(3, false);
    let switch_key = client
        .key_switching_key(&client, 0, config, &mut rng)
        .unwrap();
    let relin_key = client.relinearization_key(0, config, &mut rng).unwrap();
    let auto_key = client.automorphism_key(0, 5, config, &mut rng).unwrap();
    let wrong_contexts = [
        make_context(2, &Q, N),
        make_context(P, &[Q[2], Q[1], Q[0]], N),
        make_context(P, &Q, 64),
    ];
    for wrong in &wrong_contexts {
        assert!(BfvKeySwitcher::try_new(wrong, &switch_key).is_err());
        assert!(BfvRelinearizer::try_new(wrong, &relin_key).is_err());
        assert!(BfvAutomorphism::try_new(wrong, &auto_key).is_err());
    }
    let limited = BfvContext::try_new(context.parameters().clone()).unwrap();
    for level in [1, 2] {
        let switch = client
            .key_switching_key(&client, level, config, &mut rng)
            .unwrap();
        let relin = client.relinearization_key(level, config, &mut rng).unwrap();
        let auto = client.automorphism_key(level, 5, config, &mut rng).unwrap();
        assert!(
            matches!(BfvKeySwitcher::try_new(&limited, &switch), Err(BfvEvaluationKeyError::Level { requested, available: 1 }) if requested == level)
        );
        assert!(
            matches!(BfvRelinearizer::try_new(&limited, &relin), Err(BfvEvaluationKeyError::Level { requested, available: 1 }) if requested == level)
        );
        assert!(
            matches!(BfvAutomorphism::try_new(&limited, &auto), Err(BfvEvaluationKeyError::Level { requested, available: 1 }) if requested == level)
        );
    }
    for exponent in [0, 2, 2 * N, usize::MAX] {
        assert!(
            client
                .automorphism_key(0, exponent, config, &mut rng)
                .is_err()
        );
    }
    let mut switch = BfvKeySwitcher::try_new(&context, &switch_key).unwrap();
    let mut relin = BfvRelinearizer::try_new(&context, &relin_key).unwrap();
    let mut auto = BfvAutomorphism::try_new(&context, &auto_key).unwrap();
    let length = context.rns_poly_len(0);
    for bad_length in [0, 2 * length - 1, 2 * length + 1, 3 * length] {
        let input = BfvCiphertext::from_raw(vec![0; bad_length]);
        let mut output = BfvCiphertext::from_raw(vec![0xfeed; 2 * length]);
        assert!(catch_unwind(AssertUnwindSafe(|| switch.switch_to(&input, &mut output))).is_err());
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
        assert!(catch_unwind(AssertUnwindSafe(|| auto.apply_to(&input, &mut output))).is_err());
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
    }
    for bad_length in [0, 3 * length - 1, 3 * length + 1, 2 * length] {
        let input = BfvQuadraticCiphertext::from_raw(vec![0; bad_length]);
        let mut output = BfvCiphertext::from_raw(vec![0xfeed; 2 * length]);
        assert!(
            catch_unwind(AssertUnwindSafe(
                || relin.relinearize_to(&input, &mut output)
            ))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
    }
    let input = context.new_ciphertext(0);
    let quadratic = BfvQuadraticCiphertext::zero_raw(3 * length);
    for bad_length in [0, 2 * length - 1, 2 * length + 1] {
        let mut output = BfvCiphertext::from_raw(vec![0xfeed; bad_length]);
        assert!(catch_unwind(AssertUnwindSafe(|| switch.switch_to(&input, &mut output))).is_err());
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
        assert!(catch_unwind(AssertUnwindSafe(|| auto.apply_to(&input, &mut output))).is_err());
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
        assert!(
            catch_unwind(AssertUnwindSafe(
                || relin.relinearize_to(&quadratic, &mut output)
            ))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 0xfeed));
    }
}

#[test]
fn invalid_key_generation_is_rejected_before_sampling() {
    let context = make_context(P, &Q, N);
    let mut rng = StdRng::seed_from_u64(0x10e0_0001);
    let client = BfvClient::generate(&context, &mut rng);
    let valid = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(10),
        level_count: None,
    };
    let invalid = [
        // Product Q supports this radix; each individual q_i does not.
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(50),
            level_count: None,
        },
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(64),
            level_count: None,
        },
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: Some(DecompositionLevelCount::new(1000)),
        },
    ];
    for config in invalid {
        let mut rng = StdRng::seed_from_u64(19);
        let mut expected = StdRng::seed_from_u64(19);
        assert!(client.relinearization_key(0, config, &mut rng).is_err());
        assert!(client.automorphism_key(0, 5, config, &mut rng).is_err());
        assert!(
            client
                .key_switching_key(&client, 0, config, &mut rng)
                .is_err()
        );
        assert_eq!(rng.next_u64(), expected.next_u64());
    }
    for level in [3, usize::MAX] {
        let mut rng = StdRng::seed_from_u64(20);
        let mut expected = StdRng::seed_from_u64(20);
        assert!(client.relinearization_key(level, valid, &mut rng).is_err());
        assert!(client.automorphism_key(level, 5, valid, &mut rng).is_err());
        assert!(
            client
                .key_switching_key(&client, level, valid, &mut rng)
                .is_err()
        );
        assert_eq!(rng.next_u64(), expected.next_u64());
    }
    for exponent in [0, 2, 64, usize::MAX] {
        let mut rng = StdRng::seed_from_u64(21);
        let mut expected = StdRng::seed_from_u64(21);
        assert!(
            client
                .automorphism_key(0, exponent, valid, &mut rng)
                .is_err()
        );
        assert_eq!(rng.next_u64(), expected.next_u64());
    }
    let incompatible = [
        make_context(2, &Q, 32),
        make_context(P, &Q, 64),
        make_context(P, &[Q[2], Q[1], Q[0]], 32),
        make_context(P, &Q[..2], 32),
    ];
    for other in &incompatible {
        let source = BfvClient::generate(other, &mut rng);
        let mut rng = StdRng::seed_from_u64(22);
        let mut expected = StdRng::seed_from_u64(22);
        assert!(
            client
                .key_switching_key(&source, 0, valid, &mut rng)
                .is_err()
        );
        assert_eq!(rng.next_u64(), expected.next_u64());
    }
}
