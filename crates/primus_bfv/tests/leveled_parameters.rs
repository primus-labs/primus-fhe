//! Working-basis model binding and ordinary public-encryption circuit admission.
use dashu_int::UBig;
use primus_bfv::keys::BfvEvaluationKeyConfig;
use primus_bfv::planning::{
    BfvLeveledKeyBackend, BfvLeveledParameterError, BfvLeveledParameters, BfvLeveledRequest,
};
use primus_bfv::{BfvClient, BfvContext, BfvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const Q: [u64; 6] = [
    1152921422732787713,
    1152921409847689217,
    1152921396962590721,
    1152921311061934081,
    1152920937394077697,
    1152920907328847873,
];

fn context(n: usize, q: &[u64], t: u64) -> BfvContext {
    let moduli = q
        .iter()
        .copied()
        .map(BarrettModulus::new)
        .collect::<Vec<_>>();
    let parameters = BfvParameters::try_coefficients(
        PolyLength::new(n),
        BarrettModulus::new(t),
        &moduli,
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::CenteredBinomial { eta: 21 },
    )
    .unwrap();
    BfvContext::try_with_levels(parameters, moduli.len()).unwrap()
}

fn integer(words: &[u64]) -> UBig {
    words.iter().rev().fold(UBig::ZERO, |x, &v| (x << 64) + v)
}

#[test]
fn admitted_depth_reserves_all_future_layers_and_every_work_basis_is_smaller() {
    for (n, q, plaintext_depths) in [
        (16384, &Q[..4], [(257, 4), (65537, 3)]),
        (32768, Q.as_slice(), [(257, 7), (65537, 5)]),
    ] {
        for (t, admitted_depth) in plaintext_depths {
            let c = context(n, q, t);
            let fresh = 21 * (2 * n + 1) as u64
                + c.parameters()
                    .base_q()
                    .moduli_values()
                    .iter()
                    .fold(1u64, |v, &q| {
                        (v as u128 * (q % t) as u128 % t as u128) as u64
                    });
            for backend in [
                BfvLeveledKeyBackend::Radix16,
                BfvLeveledKeyBackend::HybridAlpha1,
            ] {
                for depth in 1..=8 {
                    let result = BfvLeveledParameters::try_new(&c, depth, backend);
                    if depth > admitted_depth {
                        assert!(matches!(
                            result,
                            Err(BfvLeveledParameterError::Budget { .. })
                        ));
                        continue;
                    }
                    let plan = result.unwrap();
                    assert_eq!(integer(plan.fresh_error_bound()), UBig::from(fresh));
                    assert_eq!(plan.steps().len(), depth);
                    let mut previous = integer(plan.fresh_error_bound());
                    let mut key_resources = std::collections::BTreeMap::new();
                    for step in plan.steps() {
                        if let BfvEvaluationKeyConfig::Hybrid(parameters) = step.key_config() {
                            let again = step.key_config();
                            let BfvEvaluationKeyConfig::Hybrid(again) = again else {
                                unreachable!()
                            };
                            assert!(std::sync::Arc::ptr_eq(&parameters, &again));
                            if let Some(previous) =
                                key_resources.insert(step.working_level(), parameters.clone())
                            {
                                assert!(std::sync::Arc::ptr_eq(&previous, &parameters));
                            }
                        }
                        assert_eq!(integer(step.input_error_bound()), previous);
                        assert!(step.working_level() > 0 && step.working_level() < c.level_count());
                        assert_eq!(step.key_backend(), backend);
                        assert!(!step.auxiliary_moduli().is_empty());
                        previous = integer(step.output_error_bound());
                        // Public codec inequality, checked independently of the planner search.
                        let mut modulus = UBig::ONE;
                        for &qi in c.parameters().base_q().moduli_values() {
                            modulus *= qi;
                        }
                        let gamma = UBig::from((1u64 << 61) - 1);
                        let r = &modulus % t;
                        assert!(
                            (previous.clone() * t + r * (t / 2)) * &gamma * 2u8
                                + &modulus * (2 * c.level_count())
                                < modulus * gamma
                        );
                    }
                }
                for depth in [0, 9] {
                    assert!(matches!(
                        BfvLeveledParameters::try_new(&c, depth, backend),
                        Err(BfvLeveledParameterError::Unsupported { .. })
                    ));
                }
            }
        }
    }
}

#[test]
fn ordinary_unsigned_public_inputs_follow_the_admitted_external_q_square_chain() {
    // Exercise the unsigned-lift budget and metadata binding at the full Q240
    // geometry. Kernel edge tests use small rings.
    let c = context(16384, &Q[..4], 257);
    let mut rng = StdRng::seed_from_u64(0x26_c0ef);
    let mut client = BfvClient::generate(&c, &mut rng);
    let pk = client.public_key(&mut rng);
    let mut encryptor = c.public_key_encryptor(&pk).unwrap();
    for backend in [
        BfvLeveledKeyBackend::Radix16,
        BfvLeveledKeyBackend::HybridAlpha1,
    ] {
        let plan = BfvLeveledParameters::try_new(&c, 2, backend).unwrap();
        let mut message = c.new_plaintext();
        message.as_mut()[..2].copy_from_slice(&[255, 3]);
        let mut encrypted = encryptor.encrypt(&message, &mut rng);
        let mut polynomial = vec![-2i64, 3];
        for step in plan.steps() {
            let key = step.relinearization_key(&client, &mut rng).unwrap();
            let mut request = step.prepare(&key).unwrap();
            assert_eq!(request.external_level(), 0);
            let mut output = c.new_ciphertext(0);
            request.square_to(&encrypted, &mut output);
            let mut next = vec![0i64; 2 * polynomial.len() - 1];
            for (i, &a) in polynomial.iter().enumerate() {
                for (j, &b) in polynomial.iter().enumerate() {
                    next[i + j] += a * b;
                }
            }
            polynomial = next;
            let mut expected = vec![0; c.parameters().poly_length().get()];
            for (out, &coefficient) in expected.iter_mut().zip(&polynomial) {
                *out = coefficient.rem_euclid(257) as u64;
            }
            assert_eq!(client.decrypt_at_level(&output, 0).as_ref(), expected);
            encrypted = output;
            // Same geometry cannot authorize another actual decomposition.
            let wrong = client
                .relinearization_key(
                    step.working_level(),
                    DecompositionConfig {
                        log_basis: DecompositionBaseLog::new(8),
                        level_count: None,
                    },
                    &mut rng,
                )
                .unwrap();
            assert!(matches!(
                step.prepare(&wrong),
                Err(BfvLeveledParameterError::Binding)
            ));
        }
    }
}

#[test]
fn admission_rejects_unsupported_gamma_incomplete_levels_or_context_owner() {
    let c = context(16384, &Q[..4], 257);
    let plan = BfvLeveledParameters::try_new(&c, 1, BfvLeveledKeyBackend::HybridAlpha1).unwrap();
    let q = c
        .parameters()
        .base_q()
        .moduli_values()
        .iter()
        .copied()
        .map(BarrettModulus::new)
        .collect::<Vec<_>>();
    for (secret, eta, gamma, levels) in [
        (SecretKeyDistr::SparseTernary, 21, (1 << 61) - 3, 4),
        (SecretKeyDistr::SparseTernary, 21, (1 << 61) - 1, 3),
    ] {
        let p = BfvParameters::try_with_decoder_modulus(
            PolyLength::new(16384),
            BarrettModulus::new(257),
            BarrettModulus::new(gamma),
            &q,
            secret,
            ErrorDistribution::CenteredBinomial { eta },
        )
        .unwrap();
        let wrong = BfvContext::try_with_levels(p, levels).unwrap();
        assert!(matches!(
            BfvLeveledParameters::try_new(&wrong, 1, BfvLeveledKeyBackend::HybridAlpha1),
            Err(BfvLeveledParameterError::Unsupported { .. })
        ));
    }
    let other = context(16384, &Q[..4], 257);
    let mut rng = StdRng::seed_from_u64(0x26_bad);
    let client = BfvClient::generate(&other, &mut rng);
    assert!(matches!(
        plan.steps()[0].relinearization_key(&client, &mut rng),
        Err(BfvLeveledParameterError::Binding)
    ));
}

fn small_request(secret: SecretKeyDistr, error: ErrorDistribution) -> BfvLeveledRequest {
    BfvLeveledRequest {
        poly_length: PolyLength::new(32),
        plaintext_modulus: 257,
        require_batching: true,
        ciphertext_prime_bits: 31,
        ciphertext_prime_count: 4,
        secret_distribution: secret,
        error_distribution: error,
    }
}

#[test]
fn custom_laws_report_public_support_and_execute_the_admitted_binary_circuit() {
    // Tiny rings exercise actual arithmetic and unsigned lifts; they are not
    // security examples. A schoolbook plaintext oracle has no scheme kernels.
    for (secret, error) in [
        (
            SecretKeyDistr::UniformBinary,
            ErrorDistribution::CenteredBinomial { eta: 2 },
        ),
        (
            SecretKeyDistr::FixedHammingWeightTernary { hamming_weight: 3 },
            ErrorDistribution::Gaussian {
                standard_deviation: 1.2,
            },
        ),
        (
            SecretKeyDistr::Gaussian {
                standard_deviation: 1.2,
            },
            ErrorDistribution::CenteredBinomial { eta: 1 },
        ),
    ] {
        let c = small_request(secret, error).create_context().unwrap();
        let mut rng = StdRng::seed_from_u64(0x14_bf01);
        let mut client = BfvClient::generate(&c, &mut rng);
        let public_key = client.public_key(&mut rng);
        let mut encryptor = c.public_key_encryptor(&public_key).unwrap();
        let mut a = c.new_plaintext();
        let mut b = c.new_plaintext();
        a.as_mut()[..2].copy_from_slice(&[256, 2]);
        b.as_mut()[..2].copy_from_slice(&[3, 256]);
        for backend in [
            BfvLeveledKeyBackend::Radix16,
            BfvLeveledKeyBackend::HybridAlpha1,
        ] {
            let plan = BfvLeveledParameters::try_new(&c, 2, backend).unwrap();
            let h = match secret {
                SecretKeyDistr::FixedHammingWeightTernary { hamming_weight } => {
                    hamming_weight as u64
                }
                _ => {
                    c.parameters()
                        .encryption_parameters()
                        .secret_key_sampler()
                        .maximum_magnitude()
                        * 32
                }
            };
            let eta = c
                .parameters()
                .encryption_parameters()
                .noise_distribution()
                .maximum_magnitude();
            assert_eq!(plan.secret_l1_bound(), h);
            assert_eq!(plan.ephemeral_l1_bound(), 32);
            let full_q = c
                .parameters()
                .base_q()
                .moduli_values()
                .iter()
                .fold(UBig::ONE, |v, &q| v * q);
            assert_eq!(
                integer(plan.fresh_error_bound()),
                UBig::from(eta) * (h + 33) + &full_q % 257u16
            );
            let encrypted_b = encryptor.encrypt(&b, &mut rng);
            let mut encrypted = encryptor.encrypt(&a, &mut rng);
            let mut expected = a.as_ref().to_vec();
            for step in plan.steps() {
                let key = step.relinearization_key(&client, &mut rng).unwrap();
                let mut operation = step.prepare(&key).unwrap();
                let mut output = c.new_ciphertext(0);
                operation.multiply_to(&encrypted, &encrypted_b, &mut output);
                let mut schoolbook = vec![0i128; 32];
                for (i, &x) in expected.iter().enumerate() {
                    for (j, &y) in b.as_ref().iter().enumerate() {
                        let value = i128::from(x) * i128::from(y);
                        if i + j < 32 {
                            schoolbook[i + j] += value;
                        } else {
                            schoolbook[i + j - 32] -= value;
                        }
                    }
                }
                expected = schoolbook
                    .into_iter()
                    .map(|x| x.rem_euclid(257) as u64)
                    .collect();
                assert_eq!(client.decrypt(&output).as_ref(), expected);
                let ledger = step.error_ledger();
                assert_eq!(
                    integer(&ledger.output_error),
                    integer(&ledger.restored_error) + integer(&ledger.restoration_drift)
                );
                assert_eq!(
                    integer(&ledger.remaining_error_capacity) + integer(&ledger.output_error),
                    integer(plan.decoder_capacity())
                );
                assert_eq!(
                    integer(&ledger.working_modulus) * integer(&ledger.restoration_multiplier),
                    full_q
                );
                encrypted = output;
            }
            for security in plan.security_inputs() {
                assert_eq!(
                    security.ephemeral_distribution,
                    Some(SecretKeyDistr::SparseTernary)
                );
                assert_eq!(security.secret_distribution, secret);
                assert_eq!(security.error_distribution, error);
            }
            if backend == BfvLeveledKeyBackend::HybridAlpha1 {
                assert!(
                    plan.security_inputs()
                        .iter()
                        .any(|x| !x.key_auxiliary_moduli.is_empty())
                );
                assert!(plan.steps().iter().all(|s| {
                    s.key_auxiliary_moduli()
                        .iter()
                        .all(|p| !c.parameters().base_q().moduli_values().contains(p))
                }));
            }
        }
    }
}

#[test]
fn request_and_budget_failures_explain_public_conditions() {
    let request = small_request(
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::CenteredBinomial { eta: 1 },
    );
    let bad = BfvLeveledRequest {
        plaintext_modulus: 15,
        ..request
    };
    assert!(
        matches!(bad.create_context(), Err(BfvLeveledParameterError::Unsupported { reason })
        if reason.contains("batching"))
    );
    let small_radix = BfvLeveledRequest {
        poly_length: PolyLength::new(32),
        plaintext_modulus: 2,
        require_batching: false,
        ciphertext_prime_bits: 16,
        ciphertext_prime_count: 3,
        ..request
    }
    .create_context()
    .unwrap();
    assert!(matches!(
        BfvLeveledParameters::try_new(&small_radix, 1, BfvLeveledKeyBackend::Radix16),
        Err(BfvLeveledParameterError::Unsupported { reason }) if reason.contains("Radix16")
    ));
    let tiny = BfvLeveledRequest {
        ciphertext_prime_bits: 20,
        ciphertext_prime_count: 2,
        require_batching: false,
        ..request
    }
    .create_context()
    .unwrap();
    let result = BfvLeveledParameters::try_new(&tiny, 8, BfvLeveledKeyBackend::Radix16);
    assert!(
        matches!(result, Err(BfvLeveledParameterError::Budget { stage: 0, required, available, .. })
        if integer(&required) > integer(&available))
    );
}
