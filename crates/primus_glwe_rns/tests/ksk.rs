//! Classic and hybrid switching retain wide Q, independent keys and auxiliary-modulus checks.
mod support;

use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{
    DcrtGlweCiphertext, DcrtGlweKeySwitchEvaluator, DcrtGlweKeySwitchingKey, DcrtGlweSecretKey,
    GlweSecretKey, HybridRnsGlweKeySwitchEvaluator, HybridRnsGlweKeySwitchingKey, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_lattice::{GlweSize, glwe::DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

/// Layout rejection must precede sampling, rather than silently truncating zip.
#[test]
fn hybrid_generation_rejects_input_secret_layout_before_sampling() {
    let q = [769u64].map(BarrettModulus::new);
    let p = [193u64].map(BarrettModulus::new);
    let table = UintDcrtTable::new(PolyLength::new(32), &[q[0], p[0]]).unwrap();
    let hybrid = primus_rns::HybridRNS::new(&q, &p, 1).unwrap();

    let parameters = support::RawParameters::new(
        GlweDimension::new(2),
        PolyLength::new(32),
        &q,
        SecretKeyDistr::UniformBinary,
        1.0,
    );
    let output_size = GlweSize::new(GlweDimension::new(1), PolyLength::new(32));
    let output_secret = GlweSecretKey::<u64>::new(
        vec![1; output_size.mask_len()],
        output_size,
        SecretKeyDistr::UniformBinary,
    );

    // Missing/extra mask polynomials and shorter/longer ring polynomials.
    for (dimension, poly_length) in [(1, 32), (3, 32), (2, 64), (2, 128)] {
        let input_size = GlweSize::new(GlweDimension::new(dimension), PolyLength::new(poly_length));
        let input_secret = GlweSecretKey::<u64>::new(
            vec![1; input_size.mask_len()],
            input_size,
            SecretKeyDistr::UniformBinary,
        );
        let mut rng = StdRng::seed_from_u64(17);
        let mut expected_rng = StdRng::seed_from_u64(17);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            HybridRnsGlweKeySwitchingKey::generate(
                &input_secret,
                parameters.encryption_parameters(),
                &output_secret,
                &hybrid,
                &table,
                &mut rng,
            )
        }));
        assert!(result.is_err(), "accepted input layout {input_size:?}");
        assert_eq!(
            rand::Rng::next_u64(&mut rng),
            rand::Rng::next_u64(&mut expected_rng),
            "sampled before rejecting input layout {input_size:?}"
        );
    }
}

#[test]
fn hybrid_noise_support_must_fit_auxiliary_moduli() {
    // Q accommodates the sampler support; P isolates the auxiliary support boundary.
    let q = [3329u64].map(BarrettModulus::new);
    let p = [257u64].map(BarrettModulus::new);
    let qp = [q[0], p[0]];
    let table = UintDcrtTable::new(PolyLength::new(32), &qp).unwrap();
    let hybrid = primus_rns::HybridRNS::new(&q, &p, 1).unwrap();

    let mut rng = StdRng::seed_from_u64(0x5150);
    for (sigma, valid) in [(21.375, true), (21.4375, false), (21.5, false)] {
        let params = support::RawParameters::new(
            GlweDimension::new(1),
            PolyLength::new(32),
            &q,
            SecretKeyDistr::UniformBinary,
            sigma,
        );
        let secret =
            GlweSecretKey::generate(params.glwe_size(), params.secret_key_sampler(), &mut rng);
        let mut rng = StdRng::seed_from_u64(17);
        let mut expected_rng = StdRng::seed_from_u64(17);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            HybridRnsGlweKeySwitchingKey::generate(
                &secret,
                params.encryption_parameters(),
                &secret,
                &hybrid,
                &table,
                &mut rng,
            )
        }));
        assert_eq!(result.is_ok(), valid);
        if !valid {
            assert_eq!(
                rand::Rng::next_u64(&mut rng),
                rand::Rng::next_u64(&mut expected_rng)
            );
        }
    }
}

/// Test RNS-based GLWE key switching end-to-end:
/// encrypt a phase probe under sk_1 → switch → inspect phase under sk_2.
#[test]
fn test_rns_glwe_ksk() {
    let dimension = 3;
    let glwe_params = support::probe_parameters(dimension);
    let poly_length = glwe_params.poly_length();
    let base = glwe_params.base_q();
    let table = UintDcrtTable::new(poly_length, base.moduli()).unwrap();
    let mut rng = StdRng::seed_from_u64(0x005e_ed4b_534b);

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let sk_1 = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let dcrt_sk_1 = DcrtGlweSecretKey::from_coeff_secret_key(&sk_1, &table);

    let sk_2 = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let dcrt_sk_2 = DcrtGlweSecretKey::from_coeff_secret_key(&sk_2, &table);

    let glev_params = glwe_params.gadget(DecompositionBaseLog::new(20), None);

    let key_switching_key = DcrtGlweKeySwitchingKey::generate(
        &sk_1,
        glwe_params.encryption_parameters(),
        &dcrt_sk_2,
        &glev_params,
        glwe_params.encryption_parameters(),
        &table,
        &mut rng,
    );

    let expected: Vec<_> = (0..poly_length.get())
        .map(|i| (i % 7) as i128 - 3)
        .collect();
    let mut c1 = DcrtGlweCiphertext::<Vec<u64>>::zero(rns_glwe_len);
    let mut c2 = DcrtGlweCiphertext::<Vec<u64>>::zero(rns_glwe_len);
    let mut ksk_evaluator =
        DcrtGlweKeySwitchEvaluator::new(&key_switching_key, &glev_params, &table);

    let dcrt_sk_1_context = dcrt_sk_1
        .try_bind_raw(
            glwe_params.encryption_parameters(),
            glwe_params.base_q(),
            &table,
        )
        .unwrap();
    dcrt_sk_1_context.encrypt_encoded_crt_to(
        &support::encode_probe(&expected, base.moduli_values()),
        &mut c1,
        &mut rng,
    );

    // Requires conversion to coefficient domain first.
    let c1 = c1.into_coeff_form(&table);

    ksk_evaluator.key_switch_to(&c1.as_view(), &mut c2.as_mut_view());

    let bound = i128::from(glwe_params.core.noise_distribution().maximum_magnitude())
        + support::switch_error_bound(
            &glev_params,
            glwe_params.encryption_parameters(),
            dimension as i128 * poly_length.get() as i128,
        );
    support::assert_probe_phase(&dcrt_sk_2, &glwe_params, &table, &c2, &expected, bound);
}

/// Test hybrid RNS gadget GLWE key switching end-to-end:
/// encrypt a phase probe under sk_1 → hybrid switch → inspect phase under sk_2.
#[test]
fn test_rns_glwe_ksk_hybrid() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length = PolyLength::new(32);

    // Three Q limbs retain an uneven partition; two P limbs keep the
    // complete integer error below each q, so the raw phase is directly testable.
    let q_values: [ValueT; 3] = [1125899906826241, 1125899906629633, 1125899906031617];
    let p_values: [ValueT; 2] = [1125899905036289, 1125899904679937];
    let q_moduli = q_values.map(<BarrettModulus<ValueT>>::new);
    let p_moduli = p_values.map(<BarrettModulus<ValueT>>::new);

    let qp_moduli_vals: Vec<BarrettModulus<ValueT>> =
        q_moduli.iter().chain(p_moduli.iter()).copied().collect();
    let qp_table = UintDcrtTable::new(poly_length, &qp_moduli_vals).unwrap();
    let q_table = UintDcrtTable::new(poly_length, &q_moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = support::RawParameters::new(
        GlweDimension::new(dimension),
        poly_length,
        &q_moduli,
        SecretKeyDistr::SparseTernary,
        3.20,
    );

    let decomposition_count = 2;
    let hybrid_rns = primus_rns::HybridRNS::new(&q_moduli, &p_moduli, decomposition_count).unwrap();

    let sk_1 = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let sk_2 = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let dcrt_sk_2 = DcrtGlweSecretKey::from_coeff_secret_key(&sk_2, &q_table);

    let dcrt_sk_1 = DcrtGlweSecretKey::from_coeff_secret_key(&sk_1, &q_table);

    let key_switching_key = HybridRnsGlweKeySwitchingKey::generate(
        &sk_1,
        glwe_params.encryption_parameters(),
        &sk_2,
        &hybrid_rns,
        &qp_table,
        &mut rng,
    );

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let expected: Vec<_> = (0..poly_length.get())
        .map(|i| (i % 7) as i128 - 3)
        .collect();
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);

    let dcrt_sk_1_context = dcrt_sk_1
        .try_bind_raw(
            glwe_params.encryption_parameters(),
            glwe_params.base_q(),
            &q_table,
        )
        .unwrap();
    dcrt_sk_1_context.encrypt_encoded_crt_to(
        &support::encode_probe(&expected, &q_values),
        &mut c1,
        &mut rng,
    );

    let mut hybrid_evaluator =
        HybridRnsGlweKeySwitchEvaluator::new(&key_switching_key, &hybrid_rns, &qp_table);

    hybrid_evaluator.key_switch_to(&c1.as_view(), &mut c2.as_mut_view());

    let p_product = u128::from(p_values[0]) * u128::from(p_values[1]);
    // Approximate ModUp uses the unreduced CRT sum, not a centered digit:
    // an r-prime partition lifts to [0, r*Qi). Here r<=2 and Qi<2P, so
    // each digit is <4P. Bound its error contribution after division by P.
    // Approximate ModDown likewise subtracts an unreduced P-basis CRT lift
    // in [0, |P|*P), rather than an exact rounded remainder. Include this
    // correction once for the body and once times the output secret L1.
    assert!(u128::from(q_values[0]) * u128::from(q_values[1]) < 2 * p_product);
    let e = i128::from(glwe_params.core.noise_distribution().maximum_magnitude());
    let secret_l1 = dimension as i128 * poly_length.get() as i128;
    let bound = e
        + 4 * secret_l1 * decomposition_count as i128 * e
        + p_values.len() as i128 * (1 + secret_l1);
    support::assert_probe_phase(&dcrt_sk_2, &glwe_params, &q_table, &c2, &expected, bound);
}

#[test]
fn phase_oracle_rejects_a_noiseless_probe_that_aliases_in_each_limb() {
    let moduli = [1125899906826241u64, 1125899906629633];
    // A wrong integer value of 1024 has small, but different, residues under
    // both primes close to 2^50. Independent distance checks would accept it
    // as a noisy encryption of zero; no common small integer error exists.
    let wrong_phase: Vec<_> = moduli
        .iter()
        .map(|&q| (1024 * support::PROBE_SCALE % i128::from(q)) as u64)
        .collect();
    assert_eq!(wrong_phase, [65_532, 851_964]);
    support::assert_phase_residues(&[123, 123], &moduli, &[0], 1_000_000);
    assert!(
        std::panic::catch_unwind(|| {
            support::assert_phase_residues(&wrong_phase, &moduli, &[0], 1_000_000)
        })
        .is_err()
    );
}
