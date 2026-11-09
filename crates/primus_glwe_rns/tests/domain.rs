//! Bindings reject numerical mismatches even when ciphertext storage has the same shape.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweAutoEvaluator, CrtGlweAutoKey, CrtGlweExpandCoeffEvaluator,
    CrtGlweExpandCoeffKey, CrtGlweExpandCoeffParallelEvaluator, CrtGlweParameters,
    CrtGlweTraceEvaluator, CrtGlweTraceKey, DcrtGadgetDomain, DcrtGlweAutoEvaluator,
    DcrtGlweAutoKey, DcrtGlweExpandCoeffEvaluator, DcrtGlweExpandCoeffKey,
    DcrtGlweExpandCoeffParallelEvaluator, DcrtGlweKeySwitchEvaluator, DcrtGlweKeySwitchingKey,
    DcrtGlwePublicKey, DcrtGlweRevTraceEvaluator, DcrtGlweRevTraceKey, DcrtGlweSecretKey,
    DcrtGlweTraceEvaluator, DcrtGlweTraceKey, GlweSecretKey, HybridRnsGlweKeySwitchEvaluator,
    HybridRnsGlweKeySwitchingKey, HybridRnsKeySwitchDomain, RnsDomainError, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_rns::{HybridRNS, HybridRNSPartitioning};
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

// Small NTT primes keep construction tests cheap; no security or post-switch noise claim.
fn parameters(
    dimension: usize,
    n: usize,
    moduli: &[BarrettModulus<u32>],
) -> CrtGlweParameters<u32, BarrettModulus<u32>> {
    CrtGlweParameters::new(
        GlweDimension::new(dimension),
        PolyLength::new(n),
        BarrettModulus::new(3),
        BarrettModulus::new(101),
        moduli,
        SecretKeyDistr::UniformBinary,
        1.0,
    )
}

#[test]
fn encryption_bindings_check_layout_and_ordered_moduli() {
    let n = PolyLength::new(32);
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, n.get(), &q);
    let table = UintDcrtTable::new(n, &q).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4249_4e44);
    let secret = GlweSecretKey::generate(params.glwe_size(), params.secret_key_sampler(), &mut rng);
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let public_key = DcrtGlwePublicKey::new(
        &key,
        params.encryption_parameters(),
        params.base_q(),
        &table,
        &mut rng,
    );
    assert!(key.try_bind(&params, &table).is_ok());
    assert!(public_key.try_bind(&params, &table).is_ok());

    // A valid table with a different N fails before the key's geometry is considered.
    let longer_table = UintDcrtTable::new(PolyLength::new(64), &q).unwrap();
    assert!(matches!(
        key.try_bind(&params, &longer_table),
        Err(RnsDomainError::PolynomialLengthMismatch { .. })
    ));
    let larger_dimension = parameters(2, n.get(), &q);
    assert!(matches!(
        key.try_bind(&larger_dimension, &table),
        Err(RnsDomainError::DimensionMismatch { .. })
    ));
    assert!(matches!(
        public_key.try_bind(&larger_dimension, &table),
        Err(RnsDomainError::DimensionMismatch { .. })
    ));

    // Each alternative parameter/table pair is itself valid and has the same shape.
    for values in [[769, 257], [257, 1153]] {
        let other_q = values.map(BarrettModulus::new);
        let other_params = parameters(1, n.get(), &other_q);
        let other_table = UintDcrtTable::new(n, &other_q).unwrap();
        // Independently supplied public-key sampling/base parts must be rejected
        // before sampling, even when the foreign base and table agree with each other.
        let mut rejected_rng = StdRng::seed_from_u64(19);
        let mut expected_rng = StdRng::seed_from_u64(19);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                DcrtGlwePublicKey::new(
                    &key,
                    params.encryption_parameters(),
                    other_params.base_q(),
                    &other_table,
                    &mut rejected_rng,
                )
            }))
            .is_err()
        );
        assert_eq!(
            rand::Rng::next_u64(&mut rejected_rng),
            rand::Rng::next_u64(&mut expected_rng)
        );
        assert!(matches!(
            key.try_bind(&other_params, &other_table),
            Err(RnsDomainError::ModulusOrderMismatch { .. })
        ));
        assert!(matches!(
            public_key.try_bind(&other_params, &other_table),
            Err(RnsDomainError::ModulusOrderMismatch { .. })
        ));
        let gadget =
            CrtGlevParameters::with_glwe_params(&other_params, DecompositionBaseLog::new(4), None);
        let domain = DcrtGadgetDomain::try_new(&gadget, &other_table).unwrap();
        assert!(matches!(
            key.try_bind_gadget(&domain),
            Err(RnsDomainError::ModulusOrderMismatch { .. })
        ));
        assert!(matches!(
            public_key.try_bind_gadget(&domain),
            Err(RnsDomainError::ModulusOrderMismatch { .. })
        ));
    }
}

#[test]
fn classic_switch_binding_checks_radix_and_retained_levels() {
    let n = PolyLength::new(32);
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, n.get(), &q);
    let table = UintDcrtTable::new(n, &q).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4741_4447);
    let secret = GlweSecretKey::generate(params.glwe_size(), params.secret_key_sampler(), &mut rng);
    let dcrt_secret = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let gadget = CrtGlevParameters::with_glwe_params(
        &params,
        DecompositionBaseLog::new(4),
        Some(DecompositionLevelCount::new(1)),
    );
    let domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
    let key = DcrtGlweKeySwitchingKey::generate(
        &secret,
        params.encryption_parameters(),
        &dcrt_secret,
        &domain,
        &mut rng,
    );
    assert!(DcrtGlweKeySwitchEvaluator::try_new(&key, &domain).is_ok());

    let other_radix = CrtGlevParameters::with_glwe_params(
        &params,
        DecompositionBaseLog::new(5),
        Some(DecompositionLevelCount::new(1)),
    );
    let other_domain = DcrtGadgetDomain::try_new(&other_radix, &table).unwrap();
    assert!(matches!(
        DcrtGlweKeySwitchEvaluator::try_new(&key, &other_domain),
        Err(RnsDomainError::DecompositionBaseLogMismatch { .. })
    ));
    let other_levels = CrtGlevParameters::with_glwe_params(
        &params,
        DecompositionBaseLog::new(4),
        Some(DecompositionLevelCount::new(2)),
    );
    let other_domain = DcrtGadgetDomain::try_new(&other_levels, &table).unwrap();
    assert!(matches!(
        DcrtGlweKeySwitchEvaluator::try_new(&key, &other_domain),
        Err(RnsDomainError::DecompositionLevelCountMismatch { .. })
    ));

    let reversed_q = [q[1], q[0]];
    let reversed_params = parameters(1, n.get(), &reversed_q);
    let reversed_table = UintDcrtTable::new(n, &reversed_q).unwrap();
    let reversed_gadget = CrtGlevParameters::with_glwe_params(
        &reversed_params,
        DecompositionBaseLog::new(4),
        Some(DecompositionLevelCount::new(1)),
    );
    let reversed_domain = DcrtGadgetDomain::try_new(&reversed_gadget, &reversed_table).unwrap();
    assert!(matches!(
        DcrtGlweKeySwitchEvaluator::try_new(&key, &reversed_domain),
        Err(RnsDomainError::ModulusOrderMismatch { .. })
    ));
}

#[test]
fn hybrid_binding_checks_qp_order_split_and_partition_width() {
    let n = PolyLength::new(32);
    let q = [257u32, 769, 1153, 3329].map(BarrettModulus::new);
    let p = [7681u32].map(BarrettModulus::new);
    let qp = [q[0], q[1], q[2], q[3], p[0]];
    let params = parameters(1, n.get(), &q);
    let table = UintDcrtTable::new(n, &qp).unwrap();
    let hybrid = HybridRNS::new(&q, &p, 2).unwrap();
    let domain = HybridRnsKeySwitchDomain::try_new(&hybrid, &table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4859_4249);
    let secret = GlweSecretKey::generate(params.glwe_size(), params.secret_key_sampler(), &mut rng);
    let key = HybridRnsGlweKeySwitchingKey::generate(
        &secret,
        params.encryption_parameters(),
        &secret,
        &domain,
        &mut rng,
    );
    assert!(HybridRnsGlweKeySwitchEvaluator::try_new(&key, &domain).is_ok());

    // Both have two active partitions, but their actual Q ranges are 2+2 and 3+1.
    let other_partitioning = HybridRNSPartitioning::new(5, 2).unwrap();
    let other = HybridRNS::from_partitioning(&q, &p, other_partitioning).unwrap();
    assert_eq!(other.partition_count(), hybrid.partition_count());
    let other_domain = HybridRnsKeySwitchDomain::try_new(&other, &table).unwrap();
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &other_domain),
        Err(RnsDomainError::PartitionWidthMismatch { .. })
    ));

    // The same flattened QP order with a different Q/P boundary is also incompatible.
    let other = HybridRNS::new(&q[..3], &[q[3], p[0]], 2).unwrap();
    let other_domain = HybridRnsKeySwitchDomain::try_new(&other, &table).unwrap();
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &other_domain),
        Err(RnsDomainError::ModuliCountMismatch { .. })
    ));
    let other_p = [BarrettModulus::new(12289u32)];
    let other_qp = [q[0], q[1], q[2], q[3], other_p[0]];
    let other_table = UintDcrtTable::new(n, &other_qp).unwrap();
    let other = HybridRNS::new(&q, &other_p, 2).unwrap();
    let other_domain = HybridRnsKeySwitchDomain::try_new(&other, &other_table).unwrap();
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &other_domain),
        Err(RnsDomainError::ModulusOrderMismatch { index: 4, .. })
    ));
    let longer_table = UintDcrtTable::new(PolyLength::new(64), &qp).unwrap();
    let other_domain = HybridRnsKeySwitchDomain::try_new(&hybrid, &longer_table).unwrap();
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &other_domain),
        Err(RnsDomainError::PolynomialLengthMismatch { .. })
    ));

    // Generation rejects an ordered-Q mismatch before consuming any coins.
    let reordered_q = [q[1], q[0], q[2], q[3]];
    let reordered_params = parameters(1, n.get(), &reordered_q);
    let mut generation_rng = StdRng::seed_from_u64(17);
    let mut expected_rng = StdRng::seed_from_u64(17);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            HybridRnsGlweKeySwitchingKey::generate(
                &secret,
                reordered_params.encryption_parameters(),
                &secret,
                &domain,
                &mut generation_rng,
            )
        }))
        .is_err()
    );
    assert_eq!(
        rand::Rng::next_u64(&mut generation_rng),
        rand::Rng::next_u64(&mut expected_rng)
    );
}

/// Key sets retain a single numerical metadata record. Every public binding must
/// consult it, including the parallel expansion constructors, before scratch
/// can be created from a foreign domain. Storage shape alone is insufficient.
#[test]
fn automorphism_bindings_check_layout_order_and_decomposition() {
    use RnsDomainError::*;

    let n = PolyLength::new(32);
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, n.get(), &q);
    let table = UintDcrtTable::new(n, &q).unwrap();
    let gadget = CrtGlevParameters::with_glwe_params(
        &params,
        DecompositionBaseLog::new(4),
        Some(DecompositionLevelCount::new(1)),
    );
    let domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4155_544f);
    let secret = GlweSecretKey::generate(params.glwe_size(), params.secret_key_sampler(), &mut rng);
    let dcrt_secret = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let crt_auto = CrtGlweAutoKey::new(&domain, 3, &secret, &dcrt_secret, &mut rng);
    let dcrt_auto = DcrtGlweAutoKey::new(&domain, 3, &dcrt_secret, &mut rng);
    let crt_trace = CrtGlweTraceKey::new(&domain, &secret, &dcrt_secret, &mut rng);
    let dcrt_trace = DcrtGlweTraceKey::new(&domain, &dcrt_secret, &mut rng);
    let reverse_trace = DcrtGlweRevTraceKey::new(&domain, &dcrt_secret, &mut rng);
    let crt_expand = CrtGlweExpandCoeffKey::new(&domain, &secret, &dcrt_secret, &mut rng);
    let dcrt_expand = DcrtGlweExpandCoeffKey::new(&domain, &dcrt_secret, &mut rng);

    // Each alternative domain is internally valid. The first one has independent
    // parameters and tables but identical values, and must be accepted.
    for (n, dimension, q, radix, levels, expected) in [
        (32, 1, &[257, 769][..], 4, 1, None),
        (
            64,
            1,
            &[257, 769][..],
            4,
            1,
            Some(PolynomialLengthMismatch {
                expected: 32,
                actual: 64,
            }),
        ),
        (
            32,
            2,
            &[257, 769][..],
            4,
            1,
            Some(DimensionMismatch {
                expected: 1,
                actual: 2,
            }),
        ),
        (
            32,
            1,
            &[257][..],
            4,
            1,
            Some(ModuliCountMismatch {
                expected: 2,
                actual: 1,
            }),
        ),
        (
            32,
            1,
            &[769, 257][..],
            4,
            1,
            Some(ModulusOrderMismatch {
                index: 0,
                expected: 257,
                actual: 769,
            }),
        ),
        (
            32,
            1,
            &[257, 1153][..],
            4,
            1,
            Some(ModulusOrderMismatch {
                index: 1,
                expected: 769,
                actual: 1153,
            }),
        ),
        (
            32,
            1,
            &[257, 769][..],
            5,
            1,
            Some(DecompositionBaseLogMismatch {
                expected: 4,
                actual: 5,
            }),
        ),
        (
            32,
            1,
            &[257, 769][..],
            4,
            2,
            Some(DecompositionLevelCountMismatch {
                expected: 1,
                actual: 2,
            }),
        ),
    ] {
        let moduli: Vec<_> = q.iter().copied().map(BarrettModulus::new).collect();
        let params = parameters(dimension, n, &moduli);
        let table = UintDcrtTable::new(PolyLength::new(n), &moduli).unwrap();
        let gadget = CrtGlevParameters::with_glwe_params(
            &params,
            DecompositionBaseLog::new(radix),
            Some(DecompositionLevelCount::new(levels)),
        );
        let domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
        let bindings = [
            (
                "CRT auto",
                CrtGlweAutoEvaluator::try_new(&crt_auto, &domain).err(),
            ),
            (
                "DCRT auto",
                DcrtGlweAutoEvaluator::try_new(&dcrt_auto, &domain).err(),
            ),
            (
                "CRT trace",
                CrtGlweTraceEvaluator::try_new(&crt_trace, &domain).err(),
            ),
            (
                "DCRT trace",
                DcrtGlweTraceEvaluator::try_new(&dcrt_trace, &domain).err(),
            ),
            (
                "reverse trace",
                DcrtGlweRevTraceEvaluator::try_new(&reverse_trace, &domain).err(),
            ),
            (
                "CRT expand",
                CrtGlweExpandCoeffEvaluator::try_new(&crt_expand, &domain).err(),
            ),
            (
                "DCRT expand",
                DcrtGlweExpandCoeffEvaluator::try_new(&dcrt_expand, &domain).err(),
            ),
            (
                "CRT parallel",
                CrtGlweExpandCoeffParallelEvaluator::try_new(&crt_expand, &domain, 2).err(),
            ),
            (
                "DCRT parallel",
                DcrtGlweExpandCoeffParallelEvaluator::try_new(&dcrt_expand, &domain, 2).err(),
            ),
        ];
        for (name, actual) in bindings {
            assert_eq!(
                actual, expected,
                "{name}, N={n}, k={dimension}, Q={q:?}, radix={radix}, levels={levels}"
            );
        }
    }
}

/// Batch preparation must reject foreign secrets before its first RNG draw.
/// These are generation checks; evaluator radix/level rejection is covered above.
#[test]
fn automorphism_key_sets_reject_foreign_secrets_before_sampling() {
    let n = PolyLength::new(32);
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, n.get(), &q);
    let table = UintDcrtTable::new(n, &q).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let secret = GlweSecretKey::generate(params.glwe_size(), params.secret_key_sampler(), &mut rng);
    let dcrt_secret = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);

    for (length, dimension, values) in [
        (64, 1, &[257, 769][..]),
        (32, 2, &[257, 769][..]),
        (32, 1, &[257][..]),
        (32, 1, &[769, 257][..]),
        (32, 1, &[257, 1153][..]),
    ] {
        let moduli: Vec<_> = values.iter().copied().map(BarrettModulus::new).collect();
        let foreign = parameters(dimension, length, &moduli);
        let foreign_table = UintDcrtTable::new(foreign.poly_length(), &moduli).unwrap();
        let gadget =
            CrtGlevParameters::with_glwe_params(&foreign, DecompositionBaseLog::new(4), None);
        let domain = DcrtGadgetDomain::try_new(&gadget, &foreign_table).unwrap();

        type KeySetGenerator<'a> = (&'a str, &'a dyn Fn(&mut StdRng));
        let generators: [KeySetGenerator<'_>; 5] = [
            ("CRT trace", &|rng| {
                let _ = CrtGlweTraceKey::new(&domain, &secret, &dcrt_secret, rng);
            }),
            ("DCRT trace", &|rng| {
                let _ = DcrtGlweTraceKey::new(&domain, &dcrt_secret, rng);
            }),
            ("reverse trace", &|rng| {
                let _ = DcrtGlweRevTraceKey::new(&domain, &dcrt_secret, rng);
            }),
            ("CRT expand", &|rng| {
                let _ = CrtGlweExpandCoeffKey::new(&domain, &secret, &dcrt_secret, rng);
            }),
            ("DCRT expand", &|rng| {
                let _ = DcrtGlweExpandCoeffKey::new(&domain, &dcrt_secret, rng);
            }),
        ];
        for (operation, generate) in generators {
            let mut rejected_rng = StdRng::seed_from_u64(4242);
            let mut expected_rng = StdRng::seed_from_u64(4242);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                generate(&mut rejected_rng)
            }));
            assert!(result.is_err(), "{operation}: foreign secret accepted");
            assert_eq!(
                rand::Rng::next_u64(&mut rejected_rng),
                rand::Rng::next_u64(&mut expected_rng),
                "{operation}: sampled before rejection"
            );
        }
    }

    // CRT generation also checks the coefficient secret when the DCRT binding is valid.
    let foreign = parameters(2, n.get(), &q);
    let foreign_secret =
        GlweSecretKey::generate(foreign.glwe_size(), foreign.secret_key_sampler(), &mut rng);
    let gadget = CrtGlevParameters::with_glwe_params(&params, DecompositionBaseLog::new(4), None);
    let domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
    for expand in [false, true] {
        let mut rejected_rng = StdRng::seed_from_u64(4242);
        let mut expected_rng = StdRng::seed_from_u64(4242);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if expand {
                    let _ = CrtGlweExpandCoeffKey::new(
                        &domain,
                        &foreign_secret,
                        &dcrt_secret,
                        &mut rejected_rng,
                    );
                } else {
                    let _ = CrtGlweTraceKey::new(
                        &domain,
                        &foreign_secret,
                        &dcrt_secret,
                        &mut rejected_rng,
                    );
                }
            }))
            .is_err()
        );
        assert_eq!(
            rand::Rng::next_u64(&mut rejected_rng),
            rand::Rng::next_u64(&mut expected_rng)
        );
    }
}
