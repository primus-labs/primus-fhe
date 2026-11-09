//! Bindings reject numerical mismatches even when ciphertext storage has the same shape.

mod support;

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe_rns::{
    CrtGlweAutoEvaluator, CrtGlweAutoKey, CrtGlweExpandCoeffEvaluator, CrtGlweExpandCoeffKey,
    CrtGlweExpandCoeffParallelEvaluator, CrtGlweTraceEvaluator, CrtGlweTraceKey,
    DcrtGlweAutoEvaluator, DcrtGlweAutoKey, DcrtGlweExpandCoeffEvaluator, DcrtGlweExpandCoeffKey,
    DcrtGlweExpandCoeffParallelEvaluator, DcrtGlweKeySwitchEvaluator, DcrtGlweKeySwitchingKey,
    DcrtGlwePublicKey, DcrtGlweRevTraceEvaluator, DcrtGlweRevTraceKey, DcrtGlweSecretKey,
    DcrtGlweTraceEvaluator, DcrtGlweTraceKey, GlweSecretKey, HybridRnsGlweKeySwitchEvaluator,
    HybridRnsGlweKeySwitchingKey, RnsDomainError, SecretKeyDistr,
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
) -> support::RawParameters<u32> {
    support::RawParameters::new(
        GlweDimension::new(dimension),
        PolyLength::new(n),
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
    assert!(
        key.try_bind_raw(params.encryption_parameters(), params.base_q(), &table)
            .is_ok()
    );
    assert!(
        public_key
            .try_bind_raw(params.encryption_parameters(), params.base_q(), &table)
            .is_ok()
    );

    // A valid table with a different N fails before the key's geometry is considered.
    let longer_table = UintDcrtTable::new(PolyLength::new(64), &q).unwrap();
    assert!(matches!(
        key.try_bind_raw(
            params.encryption_parameters(),
            params.base_q(),
            &longer_table
        ),
        Err(RnsDomainError::PolynomialLengthMismatch { .. })
    ));
    let larger_dimension = parameters(2, n.get(), &q);
    assert!(matches!(
        key.try_bind_raw(
            larger_dimension.encryption_parameters(),
            larger_dimension.base_q(),
            &table
        ),
        Err(RnsDomainError::DimensionMismatch { .. })
    ));
    assert!(matches!(
        public_key.try_bind_raw(
            larger_dimension.encryption_parameters(),
            larger_dimension.base_q(),
            &table
        ),
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
            key.try_bind_raw(
                other_params.encryption_parameters(),
                other_params.base_q(),
                &other_table
            ),
            Err(RnsDomainError::ModulusOrderMismatch { .. })
        ));
        assert!(matches!(
            public_key.try_bind_raw(
                other_params.encryption_parameters(),
                other_params.base_q(),
                &other_table
            ),
            Err(RnsDomainError::ModulusOrderMismatch { .. })
        ));
        let gadget = other_params.gadget(DecompositionBaseLog::new(4), None);
        assert!(matches!(
            key.try_bind_gadget(&gadget, other_params.encryption_parameters(), &other_table),
            Err(RnsDomainError::ModulusOrderMismatch { .. })
        ));
        assert!(matches!(
            public_key.try_bind_gadget(&gadget, other_params.encryption_parameters(), &other_table),
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
    let gadget = params.gadget(
        DecompositionBaseLog::new(4),
        Some(DecompositionLevelCount::new(1)),
    );
    let key = DcrtGlweKeySwitchingKey::generate(
        &secret,
        params.encryption_parameters(),
        &dcrt_secret,
        &gadget,
        params.encryption_parameters(),
        &table,
        &mut rng,
    );
    assert!(DcrtGlweKeySwitchEvaluator::try_new(&key, &gadget, &table).is_ok());
    let longer_table = UintDcrtTable::new(PolyLength::new(64), &q).unwrap();
    assert!(matches!(
        DcrtGlweKeySwitchEvaluator::try_new(&key, &gadget, &longer_table),
        Err(RnsDomainError::PolynomialLengthMismatch { .. })
    ));
    let reversed_table = UintDcrtTable::new(n, &[q[1], q[0]]).unwrap();
    assert!(matches!(
        DcrtGlweKeySwitchEvaluator::try_new(&key, &gadget, &reversed_table),
        Err(RnsDomainError::ModulusOrderMismatch { .. })
    ));

    let other_radix = params.gadget(
        DecompositionBaseLog::new(5),
        Some(DecompositionLevelCount::new(1)),
    );
    assert!(matches!(
        DcrtGlweKeySwitchEvaluator::try_new(&key, &other_radix, &table),
        Err(RnsDomainError::DecompositionBaseLogMismatch { .. })
    ));
    let other_levels = params.gadget(
        DecompositionBaseLog::new(4),
        Some(DecompositionLevelCount::new(2)),
    );
    assert!(matches!(
        DcrtGlweKeySwitchEvaluator::try_new(&key, &other_levels, &table),
        Err(RnsDomainError::DecompositionLevelCountMismatch { .. })
    ));

    let reversed_q = [q[1], q[0]];
    let reversed_params = parameters(1, n.get(), &reversed_q);
    let reversed_table = UintDcrtTable::new(n, &reversed_q).unwrap();
    let reversed_gadget = reversed_params.gadget(
        DecompositionBaseLog::new(4),
        Some(DecompositionLevelCount::new(1)),
    );
    assert!(matches!(
        DcrtGlweKeySwitchEvaluator::try_new(&key, &reversed_gadget, &reversed_table),
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
    let mut rng = StdRng::seed_from_u64(0x4859_4249);
    let secret = GlweSecretKey::generate(params.glwe_size(), params.secret_key_sampler(), &mut rng);
    let key = HybridRnsGlweKeySwitchingKey::generate(
        &secret,
        params.encryption_parameters(),
        &secret,
        &hybrid,
        &table,
        &mut rng,
    );
    assert!(HybridRnsGlweKeySwitchEvaluator::try_new(&key, &hybrid, &table).is_ok());
    let reordered_qp = [q[1], q[0], q[2], q[3], p[0]];
    let reordered_table = UintDcrtTable::new(n, &reordered_qp).unwrap();
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &hybrid, &reordered_table),
        Err(RnsDomainError::ModulusOrderMismatch { .. })
    ));

    // Both have two active partitions, but their actual Q ranges are 2+2 and 3+1.
    let other_partitioning = HybridRNSPartitioning::new(5, 2).unwrap();
    let other = HybridRNS::from_partitioning(&q, &p, other_partitioning).unwrap();
    assert_eq!(other.partition_count(), hybrid.partition_count());
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &other, &table),
        Err(RnsDomainError::PartitionWidthMismatch { .. })
    ));

    // The same flattened QP order with a different Q/P boundary is also incompatible.
    let other = HybridRNS::new(&q[..3], &[q[3], p[0]], 2).unwrap();
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &other, &table),
        Err(RnsDomainError::ModuliCountMismatch { .. })
    ));
    let other_p = [BarrettModulus::new(12289u32)];
    let other_qp = [q[0], q[1], q[2], q[3], other_p[0]];
    let other_table = UintDcrtTable::new(n, &other_qp).unwrap();
    let other = HybridRNS::new(&q, &other_p, 2).unwrap();
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &other, &other_table),
        Err(RnsDomainError::ModulusOrderMismatch { index: 4, .. })
    ));
    let longer_table = UintDcrtTable::new(PolyLength::new(64), &qp).unwrap();
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &hybrid, &longer_table),
        Err(RnsDomainError::PolynomialLengthMismatch { .. })
    ));

    // QP table compatibility is checked by generation itself before sampling.
    for rejected_table in [&reordered_table, &longer_table] {
        let mut rejected = StdRng::seed_from_u64(171);
        let mut untouched = StdRng::seed_from_u64(171);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                HybridRnsGlweKeySwitchingKey::generate(
                    &secret,
                    params.encryption_parameters(),
                    &secret,
                    &hybrid,
                    rejected_table,
                    &mut rejected,
                )
            }))
            .is_err()
        );
        assert_eq!(
            rand::Rng::next_u64(&mut rejected),
            rand::Rng::next_u64(&mut untouched)
        );
    }

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
                &hybrid,
                &table,
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
/// can be created from a foreign parameters. Storage shape alone is insufficient.
#[test]
fn automorphism_bindings_check_layout_order_and_decomposition() {
    use RnsDomainError::*;

    let n = PolyLength::new(32);
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, n.get(), &q);
    let table = UintDcrtTable::new(n, &q).unwrap();
    let gadget = params.gadget(
        DecompositionBaseLog::new(4),
        Some(DecompositionLevelCount::new(1)),
    );
    let mut rng = StdRng::seed_from_u64(0x4155_544f);
    let secret = GlweSecretKey::generate(params.glwe_size(), params.secret_key_sampler(), &mut rng);
    let dcrt_secret = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let crt_auto = CrtGlweAutoKey::new(
        &gadget,
        params.encryption_parameters(),
        &table,
        3,
        &secret,
        &dcrt_secret,
        &mut rng,
    );
    let dcrt_auto = DcrtGlweAutoKey::new(
        &gadget,
        params.encryption_parameters(),
        &table,
        3,
        &dcrt_secret,
        &mut rng,
    );
    let crt_trace = CrtGlweTraceKey::new(
        &gadget,
        params.encryption_parameters(),
        &table,
        &secret,
        &dcrt_secret,
        &mut rng,
    );
    let dcrt_trace = DcrtGlweTraceKey::new(
        &gadget,
        params.encryption_parameters(),
        &table,
        &dcrt_secret,
        &mut rng,
    );
    let reverse_trace = DcrtGlweRevTraceKey::new(
        &gadget,
        params.encryption_parameters(),
        &table,
        &dcrt_secret,
        &mut rng,
    );
    let crt_expand = CrtGlweExpandCoeffKey::new(
        &gadget,
        params.encryption_parameters(),
        &table,
        &secret,
        &dcrt_secret,
        &mut rng,
    );
    let dcrt_expand = DcrtGlweExpandCoeffKey::new(
        &gadget,
        params.encryption_parameters(),
        &table,
        &dcrt_secret,
        &mut rng,
    );

    let longer_table = UintDcrtTable::new(PolyLength::new(64), &q).unwrap();
    assert!(matches!(
        CrtGlweAutoEvaluator::try_new(&crt_auto, &gadget, &longer_table),
        Err(PolynomialLengthMismatch { .. })
    ));
    let reversed_table = UintDcrtTable::new(n, &[q[1], q[0]]).unwrap();
    assert!(matches!(
        CrtGlweAutoEvaluator::try_new(&crt_auto, &gadget, &reversed_table),
        Err(ModulusOrderMismatch { .. })
    ));

    // Each alternative parameter/table pair is internally valid. The first one has independent
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
        let gadget = params.gadget(
            DecompositionBaseLog::new(radix),
            Some(DecompositionLevelCount::new(levels)),
        );
        let bindings = [
            (
                "CRT auto",
                CrtGlweAutoEvaluator::try_new(&crt_auto, &gadget, &table).err(),
            ),
            (
                "DCRT auto",
                DcrtGlweAutoEvaluator::try_new(&dcrt_auto, &gadget, &table).err(),
            ),
            (
                "CRT trace",
                CrtGlweTraceEvaluator::try_new(&crt_trace, &gadget, &table).err(),
            ),
            (
                "DCRT trace",
                DcrtGlweTraceEvaluator::try_new(&dcrt_trace, &gadget, &table).err(),
            ),
            (
                "reverse trace",
                DcrtGlweRevTraceEvaluator::try_new(&reverse_trace, &gadget, &table).err(),
            ),
            (
                "CRT expand",
                CrtGlweExpandCoeffEvaluator::try_new(&crt_expand, &gadget, &table).err(),
            ),
            (
                "DCRT expand",
                DcrtGlweExpandCoeffEvaluator::try_new(&dcrt_expand, &gadget, &table).err(),
            ),
            (
                "CRT parallel",
                CrtGlweExpandCoeffParallelEvaluator::try_new(&crt_expand, &gadget, &table, 2).err(),
            ),
            (
                "DCRT parallel",
                DcrtGlweExpandCoeffParallelEvaluator::try_new(&dcrt_expand, &gadget, &table, 2)
                    .err(),
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
        let gadget = foreign.gadget(DecompositionBaseLog::new(4), None);

        type KeySetGenerator<'a> = (&'a str, &'a dyn Fn(&mut StdRng));
        let generators: [KeySetGenerator<'_>; 5] = [
            ("CRT trace", &|rng| {
                let _ = CrtGlweTraceKey::new(
                    &gadget,
                    foreign.encryption_parameters(),
                    &foreign_table,
                    &secret,
                    &dcrt_secret,
                    rng,
                );
            }),
            ("DCRT trace", &|rng| {
                let _ = DcrtGlweTraceKey::new(
                    &gadget,
                    foreign.encryption_parameters(),
                    &foreign_table,
                    &dcrt_secret,
                    rng,
                );
            }),
            ("reverse trace", &|rng| {
                let _ = DcrtGlweRevTraceKey::new(
                    &gadget,
                    foreign.encryption_parameters(),
                    &foreign_table,
                    &dcrt_secret,
                    rng,
                );
            }),
            ("CRT expand", &|rng| {
                let _ = CrtGlweExpandCoeffKey::new(
                    &gadget,
                    foreign.encryption_parameters(),
                    &foreign_table,
                    &secret,
                    &dcrt_secret,
                    rng,
                );
            }),
            ("DCRT expand", &|rng| {
                let _ = DcrtGlweExpandCoeffKey::new(
                    &gadget,
                    foreign.encryption_parameters(),
                    &foreign_table,
                    &dcrt_secret,
                    rng,
                );
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
    let gadget = params.gadget(DecompositionBaseLog::new(4), None);
    for expand in [false, true] {
        let mut rejected_rng = StdRng::seed_from_u64(4242);
        let mut expected_rng = StdRng::seed_from_u64(4242);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if expand {
                    let _ = CrtGlweExpandCoeffKey::new(
                        &gadget,
                        params.encryption_parameters(),
                        &table,
                        &foreign_secret,
                        &dcrt_secret,
                        &mut rejected_rng,
                    );
                } else {
                    let _ = CrtGlweTraceKey::new(
                        &gadget,
                        params.encryption_parameters(),
                        &table,
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

#[test]
fn independent_sampling_and_table_inputs_reject_before_key_generation() {
    let n = PolyLength::new(32);
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, n.get(), &q);
    let table = UintDcrtTable::new(n, &q).unwrap();
    let gadget = params.gadget(DecompositionBaseLog::new(4), None);
    let mut rng = StdRng::seed_from_u64(427);
    let secret = GlweSecretKey::generate(params.glwe_size(), params.secret_key_sampler(), &mut rng);
    let dcrt_secret = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let public_key = DcrtGlwePublicKey::new(
        &dcrt_secret,
        params.encryption_parameters(),
        params.base_q(),
        &table,
        &mut rng,
    );
    let longer_sampling = parameters(1, 64, &q);
    let wider_sampling = parameters(2, 32, &q);
    let reversed_sampling = parameters(1, 32, &[q[1], q[0]]);
    let longer_table = UintDcrtTable::new(PolyLength::new(64), &q).unwrap();
    let reversed_table = UintDcrtTable::new(n, &[q[1], q[0]]).unwrap();

    for (sampling, table) in [
        (longer_sampling.encryption_parameters(), &table),
        (wider_sampling.encryption_parameters(), &table),
        (reversed_sampling.encryption_parameters(), &table),
        (params.encryption_parameters(), &longer_table),
        (params.encryption_parameters(), &reversed_table),
    ] {
        assert!(
            dcrt_secret
                .try_bind_gadget(&gadget, sampling, table)
                .is_err()
        );
        assert!(
            public_key
                .try_bind_gadget(&gadget, sampling, table)
                .is_err()
        );
        // The complete key set has to validate before its first encrypted row.
        type Generator<'a> = &'a dyn Fn(&mut StdRng);
        let generators: [Generator<'_>; 5] = [
            &|rng| {
                let _ = CrtGlweTraceKey::new(&gadget, sampling, table, &secret, &dcrt_secret, rng);
            },
            &|rng| {
                let _ = DcrtGlweTraceKey::new(&gadget, sampling, table, &dcrt_secret, rng);
            },
            &|rng| {
                let _ = DcrtGlweRevTraceKey::new(&gadget, sampling, table, &dcrt_secret, rng);
            },
            &|rng| {
                let _ = CrtGlweExpandCoeffKey::new(
                    &gadget,
                    sampling,
                    table,
                    &secret,
                    &dcrt_secret,
                    rng,
                );
            },
            &|rng| {
                let _ = DcrtGlweExpandCoeffKey::new(&gadget, sampling, table, &dcrt_secret, rng);
            },
        ];
        for generate in generators {
            let mut rejected = StdRng::seed_from_u64(428);
            let mut untouched = StdRng::seed_from_u64(428);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| generate(&mut rejected)))
                    .is_err()
            );
            assert_eq!(
                rand::Rng::next_u64(&mut rejected),
                rand::Rng::next_u64(&mut untouched)
            );
        }
    }
}

/// A bad complete length must fail at the public boundary, before a scalar or
/// component zip can leave a partially updated destination.
#[test]
fn evaluation_rejects_incomplete_layouts_before_writes() {
    use primus_glwe_rns::{CrtGlweCiphertext, DcrtGlweCiphertext};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn rejects(length: usize, mut operation: impl FnMut(&[u32], &mut [u32])) {
        for (input_length, output_length) in [
            (length - 1, length),
            (length + 1, length),
            (length, length - 1),
            (length, length + 1),
        ] {
            let input = vec![0; input_length];
            let mut output = vec![1; output_length];
            assert!(catch_unwind(AssertUnwindSafe(|| operation(&input, &mut output))).is_err());
            assert!(output.iter().all(|&value| value == 1));
        }
    }

    let n = PolyLength::new(32);
    let q = [257u32, 769].map(BarrettModulus::new);
    let parameters = parameters(2, n.get(), &q);
    let table = UintDcrtTable::new(n, &q).unwrap();
    let gadget = parameters.gadget(DecompositionBaseLog::new(4), None);
    let mut rng = StdRng::seed_from_u64(0x4c45_4e47_5448);
    let secret = GlweSecretKey::generate(
        parameters.glwe_size(),
        parameters.secret_key_sampler(),
        &mut rng,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let crt_auto_key = CrtGlweAutoKey::new(
        &gadget,
        parameters.encryption_parameters(),
        &table,
        3,
        &secret,
        &key,
        &mut rng,
    );
    let dcrt_auto_key = DcrtGlweAutoKey::new(
        &gadget,
        parameters.encryption_parameters(),
        &table,
        3,
        &key,
        &mut rng,
    );
    let crt_trace_key = CrtGlweTraceKey::new(
        &gadget,
        parameters.encryption_parameters(),
        &table,
        &secret,
        &key,
        &mut rng,
    );
    let dcrt_trace_key = DcrtGlweTraceKey::new(
        &gadget,
        parameters.encryption_parameters(),
        &table,
        &key,
        &mut rng,
    );
    let reverse_key = DcrtGlweRevTraceKey::new(
        &gadget,
        parameters.encryption_parameters(),
        &table,
        &key,
        &mut rng,
    );
    let switch_key = DcrtGlweKeySwitchingKey::generate(
        &secret,
        parameters.encryption_parameters(),
        &key,
        &gadget,
        parameters.encryption_parameters(),
        &table,
        &mut rng,
    );
    let mut crt_auto = CrtGlweAutoEvaluator::new(&crt_auto_key, &gadget, &table);
    let mut dcrt_auto = DcrtGlweAutoEvaluator::new(&dcrt_auto_key, &gadget, &table);
    let mut crt_trace = CrtGlweTraceEvaluator::new(&crt_trace_key, &gadget, &table);
    let mut dcrt_trace = DcrtGlweTraceEvaluator::new(&dcrt_trace_key, &gadget, &table);
    let mut reverse = DcrtGlweRevTraceEvaluator::new(&reverse_key, &gadget, &table);
    let mut switching = DcrtGlweKeySwitchEvaluator::new(&switch_key, &gadget, &table);
    let length = parameters.rns_glwe_len();
    rejects(length, |input, output| {
        crt_auto.automorphism_to(
            &CrtGlweCiphertext::new(input),
            &mut CrtGlweCiphertext::new(output),
        )
    });
    rejects(length, |input, output| {
        dcrt_auto.automorphism_to(
            &DcrtGlweCiphertext::new(input),
            &mut DcrtGlweCiphertext::new(output),
        )
    });
    rejects(length, |input, output| {
        crt_trace.trace_to(
            &CrtGlweCiphertext::new(input),
            &mut CrtGlweCiphertext::new(output),
        )
    });
    rejects(length, |input, output| {
        dcrt_trace.trace_to(
            &DcrtGlweCiphertext::new(input),
            &mut DcrtGlweCiphertext::new(output),
        )
    });
    rejects(length, |input, output| {
        reverse.trace_to(
            &DcrtGlweCiphertext::new(input),
            &mut DcrtGlweCiphertext::new(output),
        )
    });
    rejects(length, |input, output| {
        switching.key_switch_to(
            &CrtGlweCiphertext::new(input),
            &mut DcrtGlweCiphertext::new(output),
        )
    });

    let p = [1153u32].map(BarrettModulus::new);
    let hybrid = HybridRNS::new(&q, &p, 1).unwrap();
    let qp = q.iter().chain(&p).copied().collect::<Vec<_>>();
    let qp_table = UintDcrtTable::new(n, &qp).unwrap();
    let hybrid_key = HybridRnsGlweKeySwitchingKey::generate(
        &secret,
        parameters.encryption_parameters(),
        &secret,
        &hybrid,
        &qp_table,
        &mut rng,
    );
    let mut hybrid_evaluator =
        HybridRnsGlweKeySwitchEvaluator::new(&hybrid_key, &hybrid, &qp_table);
    rejects(length, |input, output| {
        hybrid_evaluator.key_switch_to(
            &DcrtGlweCiphertext::new(input),
            &mut DcrtGlweCiphertext::new(output),
        )
    });
}
