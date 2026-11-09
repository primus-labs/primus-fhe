//! Classic and hybrid switching retain wide Q, independent keys and auxiliary-modulus checks.

use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweParameters, DcrtGadgetDomain, DcrtGlweCiphertext,
    DcrtGlweDecryptWorkspace, DcrtGlweKeySwitchEvaluator, DcrtGlweKeySwitchingKey,
    DcrtGlweSecretKey, GlweSecretKey, HybridRnsGlweKeySwitchEvaluator,
    HybridRnsGlweKeySwitchingKey, HybridRnsKeySwitchDomain, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_lattice::{GlweSize, glwe::DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

/// Layout rejection must precede sampling, rather than silently truncating zip.
#[test]
fn hybrid_generation_rejects_input_secret_layout_before_sampling() {
    let q = [769u64].map(BarrettModulus::new);
    let p = [193u64].map(BarrettModulus::new);
    let table = UintDcrtTable::new(PolyLength::new(32), &[q[0], p[0]]).unwrap();
    let hybrid = primus_rns::HybridRNS::new(&q, &p, 1).unwrap();
    let domain = HybridRnsKeySwitchDomain::try_new(&hybrid, &table).unwrap();
    let parameters = CrtGlweParameters::new(
        GlweDimension::new(2),
        PolyLength::new(32),
        BarrettModulus::new(3),
        BarrettModulus::new(101),
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
                &domain,
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
    // Q accommodates fresh plaintext recovery; P isolates the support boundary.
    let q = [3329u64].map(BarrettModulus::new);
    let p = [257u64].map(BarrettModulus::new);
    let qp = [q[0], p[0]];
    let table = UintDcrtTable::new(PolyLength::new(32), &qp).unwrap();
    let hybrid = primus_rns::HybridRNS::new(&q, &p, 1).unwrap();
    let domain = HybridRnsKeySwitchDomain::try_new(&hybrid, &table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x5150);
    for (sigma, valid) in [(21.375, true), (21.4375, false), (21.5, false)] {
        let params = CrtGlweParameters::new(
            GlweDimension::new(1),
            PolyLength::new(32),
            BarrettModulus::new(3),
            BarrettModulus::new(101),
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
                &domain,
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
/// encrypt under sk_1 → key-switch → decrypt under sk_2 → assert same plaintext.
#[test]
fn test_rns_glwe_ksk() {
    type ValueT = u64;

    let dimension = 3;
    let poly_length = PolyLength::new(32);

    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2305843009213554689;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    // Two 50-bit RNS moduli: Q = q₀ · q₁
    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(poly_length, &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(0x005e_ed4b_534b);

    let glwe_params = CrtGlweParameters::new(
        GlweDimension::new(dimension),
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.20,
    );

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

    let glev_params =
        CrtGlevParameters::with_glwe_params(&glwe_params, DecompositionBaseLog::new(20), None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let key_switching_key = DcrtGlweKeySwitchingKey::generate(
        &sk_1,
        glwe_params.encryption_parameters(),
        &dcrt_sk_2,
        &domain,
        &mut rng,
    );

    let input: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length.get(), mod_t, &mut rng);
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut ksk_evaluator = DcrtGlweKeySwitchEvaluator::new(&key_switching_key, &domain);
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    let dcrt_sk_1_context = dcrt_sk_1.try_bind(&glwe_params, &table).unwrap();
    dcrt_sk_1_context.encrypt_to(&input, &mut c1, &mut rng);

    // Requires conversion to coefficient domain first.
    let c1 = c1.into_coeff_form(&table);

    ksk_evaluator.key_switch_to(&c1.as_view(), &mut c2.as_mut_view());

    let dcrt_sk_2_context = dcrt_sk_2.try_bind(&glwe_params, &table).unwrap();
    let output = dcrt_sk_2_context.decrypt(&c2, &mut decrypt_workspace);

    assert_eq!(input.as_ref(), output.as_ref());
}

/// Test hybrid RNS gadget GLWE key switching end-to-end:
/// encrypt under sk_1 → hybrid key-switch → decrypt under sk_2 → assert same
/// plaintext.
#[test]
fn test_rns_glwe_ksk_hybrid() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length = PolyLength::new(32);

    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2305843009213554689;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    // Three 50-bit Q moduli + one 50-bit P modulus.
    let q_values: [ValueT; 3] = [1125899906826241, 1125899906629633, 1125899906031617];
    let p_values: [ValueT; 1] = [1125899905036289];
    let q_moduli = q_values.map(<BarrettModulus<ValueT>>::new);
    let p_moduli = p_values.map(<BarrettModulus<ValueT>>::new);

    let qp_moduli_vals: Vec<BarrettModulus<ValueT>> =
        q_moduli.iter().chain(p_moduli.iter()).copied().collect();
    let qp_table = UintDcrtTable::new(poly_length, &qp_moduli_vals).unwrap();
    let q_table = UintDcrtTable::new(poly_length, &q_moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = CrtGlweParameters::new(
        GlweDimension::new(dimension),
        poly_length,
        mod_t,
        mod_gamma,
        &q_moduli,
        SecretKeyDistr::SparseTernary,
        3.20,
    );

    let decomposition_count = 2;
    let hybrid_rns = primus_rns::HybridRNS::new(&q_moduli, &p_moduli, decomposition_count).unwrap();
    let hybrid_domain = HybridRnsKeySwitchDomain::try_new(&hybrid_rns, &qp_table).unwrap();

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
        &hybrid_domain,
        &mut rng,
    );

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let input: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length.get(), mod_t, &mut rng);
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);

    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    let dcrt_sk_1_context = dcrt_sk_1.try_bind(&glwe_params, &q_table).unwrap();
    dcrt_sk_1_context.encrypt_to(&input, &mut c1, &mut rng);

    let mut hybrid_evaluator =
        HybridRnsGlweKeySwitchEvaluator::new(&key_switching_key, &hybrid_domain);

    hybrid_evaluator.key_switch_to(&c1.as_view(), &mut c2.as_mut_view());

    let dcrt_sk_2_context = dcrt_sk_2.try_bind(&glwe_params, &q_table).unwrap();
    let output = dcrt_sk_2_context.decrypt(&c2, &mut decrypt_workspace);

    assert_eq!(
        input.as_ref(),
        output.as_ref(),
        "hybrid KSK decryption mismatch"
    );
}
