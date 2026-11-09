//! Ordinary public budgets are consumed by actual role keys and leveled requests.

use dashu_int::UBig;
use primus_bgv::evaluation::{
    BgvAutomorphism, BgvEvaluator, BgvKeySwitcher, BgvModulusSwitch, BgvMultiplication,
};
use primus_bgv::keys::BgvEvaluationKeyConfig;
use primus_bgv::planning::{
    BgvBudgetBackend, BgvCircuitOperation as Op, BgvCircuitPlan, BgvParameterRequest,
    BgvPlaintextBounds, BgvPlanningError,
};
use primus_bgv::{BgvClient, BgvContext, BgvParameters, BgvParametersError, PlaintextEmbedding};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;
const P: u64 = 193;

fn request(bits: u32, count: usize) -> BgvParameterRequest {
    BgvParameterRequest {
        poly_length: PolyLength::new(N),
        plaintext_modulus: P,
        ciphertext_prime_bits: bits,
        ciphertext_prime_count: count,
        level_count: count,
        secret_distribution: SecretKeyDistr::SparseTernary,
        error_distribution: ErrorDistribution::CenteredBinomial { eta: 1 },
    }
}

fn radix() -> BgvBudgetBackend {
    BgvBudgetBackend::Radix(DecompositionConfig {
        log_basis: DecompositionBaseLog::new(7),
        level_count: None,
    })
}

fn bounds(coefficients: &[u64]) -> BgvPlaintextBounds {
    BgvPlaintextBounds::try_new(
        PolyLength::new(N),
        BarrettModulus::new(P),
        coefficients,
        PlaintextEmbedding::Centered,
    )
    .unwrap()
}

fn multiply(lhs: &[u64], rhs: &[u64]) -> Vec<u64> {
    let mut out = vec![0i128; N];
    for (i, &left) in lhs.iter().enumerate() {
        for (j, &right) in rhs.iter().enumerate() {
            out[(i + j) % N] +=
                i128::from(left) * i128::from(right) * if i + j < N { 1 } else { -1 };
        }
    }
    out.into_iter()
        .map(|x| x.rem_euclid(i128::from(P)) as u64)
        .collect()
}

#[test]
fn both_actual_key_backends_consume_the_full_public_dag() {
    let context = request(32, 3).create_context().unwrap();
    let mut one = context.new_plaintext();
    one.as_mut()[0] = 1;
    let mut factor = context.new_plaintext();
    factor.as_mut()[..2].copy_from_slice(&[2, 1]);
    let operations = [
        Op::PublicEncryption {
            embedding: PlaintextEmbedding::Centered,
        },
        Op::PublicEncryption {
            embedding: PlaintextEmbedding::Centered,
        },
        Op::Add { lhs: 0, rhs: 1 },
        Op::MultiplyPlain {
            input: 2,
            plaintext: bounds(factor.as_ref()),
        },
        Op::Multiply { lhs: 3, rhs: 0 },
        Op::Multiply { lhs: 4, rhs: 4 },
        Op::DropPrime { input: 5 },
        Op::Automorphism {
            input: 6,
            exponent: 5,
        },
        Op::KeySwitch { input: 7 },
        Op::AddPlain {
            input: 8,
            plaintext: bounds(one.as_ref()),
        },
        Op::DropPrime { input: 9 },
    ];
    for backend in [
        radix(),
        BgvBudgetBackend::hybrid(&context, 3, 32, 1).unwrap(),
    ] {
        let hybrid = matches!(backend, BgvBudgetBackend::Hybrid { .. });
        let plan = BgvCircuitPlan::try_new(&context, &operations, backend).unwrap();
        if hybrid {
            let (
                Some(BgvEvaluationKeyConfig::Hybrid(top)),
                Some(BgvEvaluationKeyConfig::Hybrid(lower)),
            ) = (plan.key_config(0), plan.key_config(1))
            else {
                panic!("each key-bearing level must retain its Hybrid configuration");
            };
            assert!(std::sync::Arc::ptr_eq(top.auxiliary(), lower.auxiliary()));
        }
        assert_eq!(plan.steps()[0].phase_bound, UBig::from(12_641u64));
        assert_eq!(plan.steps().last().unwrap().level, 2);
        assert!(plan.key_config(2).is_none());
        for step in plan.steps() {
            assert_eq!(
                step.terms
                    .iter()
                    .fold(UBig::ZERO, |sum, term| sum + &term.bound),
                step.phase_bound
            );
            assert_eq!(&step.phase_bound + &step.margin, step.capacity);
        }
        let mut rng = StdRng::seed_from_u64(0x14_b6);
        let alice = BgvClient::generate(&context, &mut rng);
        let mut bob = BgvClient::generate(&context, &mut rng);
        let public_key = alice.public_key(&mut rng);
        let mut encryptor = context.public_key_encryptor(&public_key).unwrap();
        let relin = alice
            .relinearization_key(0, plan.key_config(0).unwrap(), &mut rng)
            .unwrap();
        let auto = alice
            .automorphism_key(1, 5, plan.key_config(1).unwrap(), &mut rng)
            .unwrap();
        let switch = bob
            .key_switching_key(&alice, 1, plan.key_config(1).unwrap(), &mut rng)
            .unwrap();
        let mut multiplication = BgvMultiplication::try_new(&context, &relin).unwrap();
        let mut automorphism = BgvAutomorphism::try_new(&context, &auto).unwrap();
        let mut switching = BgvKeySwitcher::try_new(&context, &switch).unwrap();
        let mut evaluator = BgvEvaluator::new(&context, 0);
        let mut lower_evaluator = BgvEvaluator::new(&context, 1);
        let mut first_drop = BgvModulusSwitch::new(&context, 0);
        let mut second_drop = BgvModulusSwitch::new(&context, 1);
        let mut a = context.new_plaintext();
        let mut b = context.new_plaintext();
        for (index, (left, right)) in a.as_mut().iter_mut().zip(b.as_mut()).enumerate() {
            *left = (7 * index as u64 + 1) % P;
            *right = (11 * index as u64 + 3) % P;
        }
        let ca = encryptor.encrypt_centered(&a, &mut rng);
        let cb = encryptor.encrypt_centered(&b, &mut rng);
        let mut work = context.new_ciphertext(0);
        let mut product = context.new_ciphertext(0);
        evaluator.add_to(&ca, &cb, &mut work);
        evaluator.mul_plain_to(&work, &factor, &mut product, PlaintextEmbedding::Centered);
        multiplication.multiply_to(&product, &ca, &mut work);
        multiplication.square_assign(&mut work);
        let mut lower = context.new_ciphertext(1);
        let mut transformed = context.new_ciphertext(1);
        let mut switched = context.new_ciphertext(1);
        let mut lowest = context.new_ciphertext(2);
        first_drop.switch_to(&work, &mut lower);
        automorphism.apply_to(&lower, &mut transformed);
        switching.switch_to(&transformed, &mut switched);
        lower_evaluator.add_plain_assign(&mut switched, &one, PlaintextEmbedding::Centered);
        second_drop.switch_to(&switched, &mut lowest);
        let sum = a
            .as_ref()
            .iter()
            .zip(b.as_ref())
            .map(|(&x, &y)| (x + y) % P)
            .collect::<Vec<_>>();
        let linear = multiply(&sum, factor.as_ref());
        let ab = multiply(&linear, a.as_ref());
        let squared = multiply(&ab, &ab);
        let mut expected = vec![0; N];
        for (degree, &value) in squared.iter().enumerate() {
            let target = 5 * degree % (2 * N);
            expected[target % N] = if target < N { value } else { (P - value) % P };
        }
        expected[0] = (expected[0] + 1) % P;
        assert_eq!(bob.decrypt(&lowest).as_ref(), expected);
    }
}

#[test]
fn admission_rejections_and_composite_plaintext_key_generation() {
    for plaintext_modulus in [0, 1, 1 << 62] {
        let mut invalid = request(30, 2);
        invalid.plaintext_modulus = plaintext_modulus;
        assert!(matches!(
            invalid.create_context(),
            Err(BgvPlanningError::Parameters(
                BgvParametersError::PlainModulus
            ))
        ));
    }

    let context = request(18, 1).create_context().unwrap();
    let fresh = Op::PublicEncryption {
        embedding: PlaintextEmbedding::Centered,
    };
    let error = BgvCircuitPlan::try_new(
        &context,
        &[fresh.clone(), Op::Multiply { lhs: 0, rhs: 0 }],
        radix(),
    )
    .err()
    .unwrap();
    assert!(matches!(
        error,
        BgvPlanningError::Recovery {
            node: 1,
            level: 0,
            required_modulus_bits: 34,
            ..
        }
    ));
    for operation in [
        Op::Add { lhs: 0, rhs: 1 },
        Op::DropPrime { input: 0 },
        Op::Automorphism {
            input: 0,
            exponent: 2,
        },
    ] {
        assert!(matches!(
            BgvCircuitPlan::try_new(&context, &[fresh.clone(), operation], radix()),
            Err(BgvPlanningError::Circuit { node: 1, .. })
        ));
    }

    // The largest nine-bit NTT prime is 449 and divides this composite p.
    // Generation must skip it rather than returning a backend rejected later.
    let mut request = request(30, 2);
    request.plaintext_modulus = 898;
    let context = request.create_context().unwrap();
    let backend = BgvBudgetBackend::hybrid(&context, 2, 9, 1).unwrap();
    match &backend {
        BgvBudgetBackend::Hybrid {
            auxiliary_moduli, ..
        } => assert_eq!(auxiliary_moduli, &[257]),
        BgvBudgetBackend::Radix(_) => unreachable!("requested Hybrid backend"),
    }
    let plan = BgvCircuitPlan::try_new(
        &context,
        &[
            Op::PrivateEncryption {
                embedding: PlaintextEmbedding::Centered,
            },
            Op::Automorphism {
                input: 0,
                exponent: 5,
            },
        ],
        backend,
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0x14_c0);
    let mut client = BgvClient::generate(&context, &mut rng);
    let key = client
        .automorphism_key(0, 5, plan.key_config(0).unwrap(), &mut rng)
        .unwrap();
    let mut operation = BgvAutomorphism::try_new(&context, &key).unwrap();
    let mut message = context.new_plaintext();
    message.as_mut()[0] = 3;
    let input = client.encrypt_centered(&message, &mut rng);
    let mut output = context.new_ciphertext(0);
    operation.apply_to(&input, &mut output);
    assert_eq!(client.decrypt(&output), message);
}

#[test]
fn public_ephemeral_support_is_independent_of_secret_support() {
    let mut request = request(32, 1);
    request.secret_distribution = SecretKeyDistr::Gaussian {
        standard_deviation: 1.0,
    };
    let context = request.create_context().unwrap();
    let operations = [
        Op::PublicEncryption {
            embedding: PlaintextEmbedding::Unsigned,
        },
        Op::PrivateEncryption {
            embedding: PlaintextEmbedding::Centered,
        },
    ];
    let plan = BgvCircuitPlan::try_new(&context, &operations, radix()).unwrap();
    // Gaussian secret hard support is 12, while public r is still exactly CBD1.
    assert_eq!(
        plan.steps()[0].phase_bound,
        UBig::from(192u64 + 193 * (32 + 1 + 32 * 12))
    );
    assert_eq!(plan.steps()[1].phase_bound, UBig::from(96u64 + 193));
    assert_eq!(
        plan.security_inputs()[0].ephemeral_distribution,
        Some(SecretKeyDistr::SparseTernary)
    );
}

#[test]
fn general_prime_plan_tracks_same_level_factor_histories_and_alignment() {
    const PLAIN: u64 = 17;
    let moduli = [12_289, 40_961, 65_537].map(BarrettModulus::new);
    let context = BgvContext::try_with_levels(
        BgvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(PLAIN),
            &moduli,
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
        3,
    )
    .unwrap();
    let mut one = vec![0; N];
    one[0] = 1;
    let plain = BgvPlaintextBounds::try_new(
        PolyLength::new(N),
        BarrettModulus::new(PLAIN),
        &one,
        PlaintextEmbedding::Centered,
    )
    .unwrap();
    let operations = [
        Op::PrivateEncryption {
            embedding: PlaintextEmbedding::Centered,
        },
        Op::Multiply { lhs: 0, rhs: 0 },
        Op::DropPrime { input: 0 },
        Op::DropPrime { input: 1 },
        Op::Multiply { lhs: 2, rhs: 3 },
        Op::Add { lhs: 2, rhs: 4 },
        Op::AddPlain {
            input: 2,
            plaintext: plain.clone(),
        },
        Op::MultiplyPlain {
            input: 6,
            plaintext: plain,
        },
        Op::Automorphism {
            input: 7,
            exponent: 5,
        },
        Op::KeySwitch { input: 8 },
        Op::DropPrime { input: 9 },
        Op::Subtract { lhs: 2, rhs: 4 },
    ];
    let plan = BgvCircuitPlan::try_new(&context, &operations, radix()).unwrap();
    let steps = plan.steps();
    assert_eq!(steps[0].phase_bound, UBig::from(25u8));
    assert_eq!(steps[0].correction_factor, 1);
    assert_eq!(steps[1].correction_factor, 1);
    // 65537 = 2 mod17, whose inverse is9. Squaring at this lower level
    // gives factor13; thus a level alone cannot determine the message factor.
    assert_eq!(steps[2].correction_factor, 9);
    assert_eq!(steps[3].correction_factor, 9);
    assert_eq!(steps[4].correction_factor, 13);
    let inverse = |value| (1..PLAIN).find(|&x| value * x % PLAIN == 1).unwrap();
    let factor = steps[5].correction_factor;
    let left = factor * inverse(steps[2].correction_factor) % PLAIN;
    let right = factor * inverse(steps[4].correction_factor) % PLAIN;
    let norm = |scale: u64| scale.min(PLAIN - scale);
    assert_eq!(
        steps[5].phase_bound,
        &steps[2].phase_bound * norm(left) + &steps[4].phase_bound * norm(right)
    );
    assert_eq!(steps[6].phase_bound, &steps[2].phase_bound + PLAIN / 2);
    assert_eq!(steps[7].phase_bound, steps[6].phase_bound);
    for step in &steps[6..10] {
        assert_eq!(step.correction_factor, 9);
    }
    // The next dropped prime is8 mod17, with inverse15.
    assert_eq!(steps[10].correction_factor, 16);
    assert_eq!(steps[11].correction_factor, steps[5].correction_factor);
    assert_eq!(steps[11].phase_bound, steps[5].phase_bound);
    for step in steps {
        assert!((1..PLAIN).contains(&step.correction_factor));
        assert_eq!(&step.phase_bound + &step.margin, step.capacity);
    }
}
