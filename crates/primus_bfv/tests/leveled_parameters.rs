//! Finite-profile model binding and ordinary public-encryption circuit admission.
use dashu_int::UBig;
use primus_bfv::{
    BfvClient, BfvContext, BfvEvaluationKeyConfig, BfvLeveledKeyBackend, BfvLeveledParameterError,
    BfvLeveledParameters, BfvLeveledProfile, BfvParameters,
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn integer(words: &[u64]) -> UBig {
    words.iter().rev().fold(UBig::ZERO, |x, &v| (x << 64) + v)
}

#[test]
fn admitted_depth_reserves_all_future_layers_and_every_work_basis_is_smaller() {
    for profile in [BfvLeveledProfile::N16384Q240, BfvLeveledProfile::N32768Q360] {
        for t in [257, 65537] {
            let c = profile.create_context(t).unwrap();
            let n = c.parameters().poly_length().get();
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
                let mut greatest = 0;
                for depth in 1..=8 {
                    let Ok(plan) = BfvLeveledParameters::try_new(&c, depth, backend) else {
                        continue;
                    };
                    greatest = depth;
                    assert_eq!(plan.profile(), profile);
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
                assert!(
                    greatest >= 2,
                    "each shipped model must admit a meaningful chain"
                );
                for depth in [0, 9] {
                    assert!(matches!(
                        BfvLeveledParameters::try_new(&c, depth, backend),
                        Err(BfvLeveledParameterError::Budget)
                    ));
                }
            }
        }
    }
}

#[test]
fn ordinary_unsigned_public_inputs_follow_the_admitted_external_q_square_chain() {
    // Full dimension is necessary here: this exercises the exact shipped model,
    // metadata binding and unsigned-lift budget; kernel edge tests use small rings.
    let c = BfvLeveledProfile::N16384Q240.create_context(257).unwrap();
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
            assert_eq!(client.decrypt(&output, 0).as_ref(), expected);
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
fn finite_admission_rejects_another_noise_secret_gamma_or_context_owner() {
    let c = BfvLeveledProfile::N16384Q240.create_context(257).unwrap();
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
        (SecretKeyDistr::UniformTernary, 21, (1 << 61) - 1, 4),
        (SecretKeyDistr::SparseTernary, 22, (1 << 61) - 1, 4),
        (SecretKeyDistr::SparseTernary, 21, (1 << 61) - 3, 4),
        (SecretKeyDistr::SparseTernary, 21, (1 << 61) - 1, 3),
    ] {
        let p = BfvParameters::try_with_error_distribution(
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
            Err(BfvLeveledParameterError::Model)
        ));
    }
    let other = BfvLeveledProfile::N16384Q240.create_context(257).unwrap();
    let mut rng = StdRng::seed_from_u64(0x26_bad);
    let client = BfvClient::generate(&other, &mut rng);
    assert!(matches!(
        plan.steps()[0].relinearization_key(&client, &mut rng),
        Err(BfvLeveledParameterError::Binding)
    ));
    assert!(BfvLeveledProfile::N16384Q240.create_context(17).is_err());
}
