use primus_bgv::{
    BgvCiphertext, BgvClient, BgvContext, BgvParameters, ErrorDistribution, SecretKeyDistr,
    advanced::BgvQuadraticCiphertext,
    evaluation::{BgvAutomorphism, BgvKeySwitcher, BgvRelinearizer},
    keys::{
        BgvAutomorphismKey, BgvEvaluationKeyError as Error, BgvKeySwitchingKey,
        BgvRelinearizationKey,
    },
};
use primus_decompose::{
    ApproxSignedBasisError as BasisError, DecompositionBaseLog, DecompositionConfig,
    DecompositionLevelCount,
};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
const P: u64 = 193;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];

fn parameters(n: usize, p: u64, q: &[u64]) -> BgvParameters {
    BgvParameters::try_coefficients(
        PolyLength::new(n),
        BarrettModulus::new(p),
        &q.iter()
            .copied()
            .map(BarrettModulus::new)
            .collect::<Vec<_>>(),
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::CenteredBinomial { eta: 1 },
    )
    .unwrap()
}

fn context(n: usize, p: u64, q: &[u64]) -> BgvContext {
    BgvContext::try_with_levels(parameters(n, p, q), q.len()).unwrap()
}

fn radix(log_basis: u32, levels: Option<usize>) -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(log_basis),
        level_count: levels.map(DecompositionLevelCount::new),
    }
}

fn role_keys(
    client: &BgvClient<'_>,
    level: usize,
    rng: &mut StdRng,
) -> (
    BgvKeySwitchingKey,
    BgvRelinearizationKey,
    BgvAutomorphismKey,
) {
    let config = radix(10, None);
    (
        client
            .key_switching_key(client, level, config, rng)
            .unwrap(),
        client.relinearization_key(level, config, rng).unwrap(),
        client.automorphism_key(level, 5, config, rng).unwrap(),
    )
}

type ErrorCheck = fn(&Error) -> bool;

#[track_caller]
fn assert_errors<const N: usize>(
    errors: [Option<Error>; N],
    matches_error: impl Fn(&Error) -> bool,
) {
    for error in errors {
        let error = error.expect("invalid evaluation key request accepted");
        assert!(
            matches_error(&error),
            "unexpected evaluation key error: {error:?}"
        );
    }
}

fn check_key_generation(
    client: &BgvClient<'_>,
    level: usize,
    config: DecompositionConfig,
    seed: u64,
    matches_error: impl Fn(&Error) -> bool,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut expected = StdRng::seed_from_u64(seed);
    assert_errors(
        [
            client.relinearization_key(level, config, &mut rng).err(),
            client.automorphism_key(level, 5, config, &mut rng).err(),
            client
                .key_switching_key(client, level, config, &mut rng)
                .err(),
        ],
        matches_error,
    );
    assert_eq!(rng.next_u64(), expected.next_u64());
}

#[test]
fn invalid_key_generation_is_rejected_before_sampling() {
    let context = context(N, P, &Q);
    let mut rng = StdRng::seed_from_u64(0x10e0_0001);
    let client = BgvClient::generate(&context, &mut rng);
    let invalid: [(_, ErrorCheck); 3] = [
        // Product Q supports this radix; each individual q_i does not.
        (
            radix(50, None),
            |error| matches!(error, Error::Radix { radix, modulus } if *radix == 1 << 50 && *modulus == Q[0]),
        ),
        (radix(64, None), |error| {
            matches!(
                error,
                Error::Decomposition(BasisError::InvalidLogBasis { .. })
            )
        }),
        (radix(10, Some(1000)), |error| {
            matches!(
                error,
                Error::Decomposition(BasisError::LevelCountTooLarge { .. })
            )
        }),
    ];
    for (config, matches_error) in invalid {
        check_key_generation(&client, 0, config, 19, matches_error);
    }
    let valid = radix(10, None);
    for level in [Q.len(), usize::MAX] {
        check_key_generation(
            &client,
            level,
            valid,
            20,
            |error| matches!(error, Error::Level { requested, available: 3 } if *requested == level),
        );
    }
    for exponent in [0, 2, 2 * N, usize::MAX] {
        let mut rng = StdRng::seed_from_u64(21);
        let mut expected = StdRng::seed_from_u64(21);
        assert_errors(
            [client.automorphism_key(0, exponent, valid, &mut rng).err()],
            |error| matches!(error, Error::Exponent { exponent: actual, twice_n } if *actual == exponent && *twice_n == 2 * N),
        );
        assert_eq!(rng.next_u64(), expected.next_u64());
    }
}

#[test]
fn evaluation_keys_reject_incompatible_domains_and_unprepared_levels() {
    let owner = context(N, P, &Q);
    let mut rng = StdRng::seed_from_u64(0x10b6_bad0);
    let client = BgvClient::generate(&owner, &mut rng);
    let (switch, relin, auto) = role_keys(&client, 0, &mut rng);
    let foreign: [(_, ErrorCheck); 4] = [
        (context(N, 2, &Q), |error| {
            matches!(
                error,
                Error::PlainModulus {
                    expected: P,
                    actual: 2
                }
            )
        }),
        (context(64, P, &Q), |error| {
            matches!(
                error,
                Error::PolynomialLength {
                    expected: N,
                    actual: 64
                }
            )
        }),
        (
            context(N, P, &[Q[2], Q[1], Q[0]]),
            |error| matches!(error, Error::Modulus { index: 0, expected, actual } if *expected == Q[0] && *actual == Q[2]),
        ),
        (context(N, P, &Q[..2]), |error| {
            matches!(
                error,
                Error::ModuliCount {
                    expected: 3,
                    actual: 2
                }
            )
        }),
    ];
    for (other, matches_error) in foreign {
        let source = BgvClient::generate(&other, &mut rng);
        let mut generation = StdRng::seed_from_u64(22);
        let mut expected = StdRng::seed_from_u64(22);
        assert_errors(
            [
                client
                    .key_switching_key(&source, 0, radix(10, None), &mut generation)
                    .err(),
                BgvKeySwitcher::try_new(&other, &switch).err(),
                BgvRelinearizer::try_new(&other, &relin).err(),
                BgvAutomorphism::try_new(&other, &auto).err(),
            ],
            matches_error,
        );
        assert_eq!(generation.next_u64(), expected.next_u64());
    }

    let unprepared = BgvContext::try_new(parameters(N, P, &Q)).unwrap();
    for level in [1, 2] {
        let (switch, relin, auto) = role_keys(&client, level, &mut rng);
        assert_errors(
            [
                BgvKeySwitcher::try_new(&unprepared, &switch).err(),
                BgvRelinearizer::try_new(&unprepared, &relin).err(),
                BgvAutomorphism::try_new(&unprepared, &auto).err(),
            ],
            |error| matches!(error, Error::Level { requested, available: 1 } if *requested == level),
        );
    }
}

#[track_caller]
fn assert_rejected_before_write(
    output: &mut BgvCiphertext<Vec<u64>>,
    operation: impl FnOnce(&mut BgvCiphertext<Vec<u64>>),
) {
    let before = output.clone();
    assert!(catch_unwind(AssertUnwindSafe(|| operation(output))).is_err());
    assert_eq!(*output, before);
}

#[test]
fn evaluation_keys_reject_bad_storage_before_writes() {
    let context = context(N, P, &Q);
    let mut rng = StdRng::seed_from_u64(0x10b6_bad0);
    let client = BgvClient::generate(&context, &mut rng);
    let (switch_key, relin_key, auto_key) = role_keys(&client, 0, &mut rng);
    let mut switch = BgvKeySwitcher::try_new(&context, &switch_key).unwrap();
    let mut relin = BgvRelinearizer::try_new(&context, &relin_key).unwrap();
    let mut auto = BgvAutomorphism::try_new(&context, &auto_key).unwrap();
    let len = context.rns_poly_len(0);
    let mut output = BgvCiphertext::from_raw(vec![0xfeed; 2 * len]);

    // Check empty, partial, oversized and the other ciphertext arity.
    for (linear_len, quadratic_len) in [
        (0, 0),
        (2 * len - 1, 3 * len - 1),
        (2 * len + 1, 3 * len + 1),
        (3 * len, 2 * len),
    ] {
        let linear = BgvCiphertext::zero_raw(linear_len);
        let quadratic = BgvQuadraticCiphertext::zero_raw(quadratic_len);
        assert_rejected_before_write(&mut output, |out| switch.switch_to(&linear, out));
        assert_rejected_before_write(&mut output, |out| auto.apply_to(&linear, out));
        assert_rejected_before_write(&mut output, |out| relin.relinearize_to(&quadratic, out));
    }

    let linear = context.new_ciphertext(0);
    let quadratic = context.new_quadratic_ciphertext(0);
    for bad_len in [0, 2 * len - 1, 2 * len + 1] {
        let mut output = BgvCiphertext::from_raw(vec![0xfeed; bad_len]);
        assert_rejected_before_write(&mut output, |out| switch.switch_to(&linear, out));
        assert_rejected_before_write(&mut output, |out| auto.apply_to(&linear, out));
        assert_rejected_before_write(&mut output, |out| relin.relinearize_to(&quadratic, out));
    }
}
