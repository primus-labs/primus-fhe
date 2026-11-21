//! Bindings reject numerical mismatches even when ciphertext storage has the same shape.

mod support;

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweAutoEvaluator, CrtGlweAutoKey, CrtGlweEncryptionParameters,
    CrtGlweExpandCoeffEvaluator, CrtGlweExpandCoeffKey, CrtGlweExpandCoeffParallelEvaluator,
    CrtGlweTraceEvaluator, CrtGlweTraceKey, DcrtGlweAutoEvaluator, DcrtGlweAutoKey,
    DcrtGlweExpandCoeffEvaluator, DcrtGlweExpandCoeffKey, DcrtGlweExpandCoeffParallelEvaluator,
    DcrtGlweKeySwitchEvaluator, DcrtGlweKeySwitchingKey, DcrtGlweRevTraceEvaluator,
    DcrtGlweRevTraceKey, DcrtGlweTraceEvaluator, DcrtGlweTraceKey, GlweSecretKey,
    HybridRnsGlweKeySwitchEvaluator, HybridRnsGlweKeySwitchingKey, RnsDomainError, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_rns::{HybridRNS, HybridRNSPartitioning, RNSBase};
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
    let table = params.ntt_table();
    let mut rng = StdRng::seed_from_u64(0x4249_4e44);
    let (_, key) = params.generate_key_pair(&table, &mut rng);
    let public_key = key
        .try_bind_raw(params.encryption_parameters(), params.base_q(), &table)
        .unwrap()
        .public_key(&mut rng);
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
        assert!(matches!(
            key.try_bind_raw(
                params.encryption_parameters(),
                other_params.base_q(),
                &other_table,
            )
            .map(|binding| binding.public_key(&mut rejected_rng)),
            Err(RnsDomainError::ModulusOrderMismatch { .. })
        ));
        assert_eq!(
            rand::Rng::next_u64(&mut rejected_rng),
            rand::Rng::next_u64(&mut expected_rng)
        );
        let sampling = other_params.encryption_parameters();
        let base = other_params.base_q();
        let gadget = other_params.gadget(DecompositionBaseLog::new(4), None);
        for (operation, result) in [
            (
                "secret raw",
                key.try_bind_raw(sampling, base, &other_table).map(|_| ()),
            ),
            (
                "public raw",
                public_key
                    .try_bind_raw(sampling, base, &other_table)
                    .map(|_| ()),
            ),
            (
                "secret gadget",
                key.try_bind_gadget(&gadget, sampling, &other_table)
                    .map(|_| ()),
            ),
            (
                "public gadget",
                public_key
                    .try_bind_gadget(&gadget, sampling, &other_table)
                    .map(|_| ()),
            ),
        ] {
            assert!(
                matches!(result, Err(RnsDomainError::ModulusOrderMismatch { .. })),
                "{operation}: {result:?} for {values:?}",
            );
        }
    }
}

#[test]
fn classic_switch_binding_checks_radix_and_retained_levels() {
    let n = PolyLength::new(32);
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, n.get(), &q);
    let table = params.ntt_table();
    let mut rng = StdRng::seed_from_u64(0x4741_4447);
    let (secret, dcrt_secret) = params.generate_key_pair(&table, &mut rng);
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

fn crt_automorphism_key(
    params: &support::RawParameters<u32>,
    gadget: &CrtGlevParameters<u32, BarrettModulus<u32>>,
    table: &UintDcrtTable<u32>,
) -> CrtGlweAutoKey<u32> {
    let mut rng = StdRng::seed_from_u64(0x4155_544f);
    let (secret, dcrt_secret) = params.generate_key_pair(table, &mut rng);
    CrtGlweAutoKey::new(
        gadget,
        params.encryption_parameters(),
        table,
        3,
        &secret,
        &dcrt_secret,
        &mut rng,
    )
}

#[test]
fn automorphism_binding_accepts_independently_prepared_matching_resources() {
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, 32, &q);
    let radix = DecompositionBaseLog::new(4);
    let levels = Some(DecompositionLevelCount::new(1));
    let key = crt_automorphism_key(&params, &params.gadget(radix, levels), &params.ntt_table());
    let equivalent = parameters(1, 32, &q);
    assert!(
        CrtGlweAutoEvaluator::try_new(
            &key,
            &equivalent.gadget(radix, levels),
            &equivalent.ntt_table(),
        )
        .is_ok()
    );
}

#[test]
fn automorphism_bindings_check_layout_order_and_decomposition() {
    use RnsDomainError::*;

    let n = PolyLength::new(32);
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, n.get(), &q);
    let table = params.ntt_table();
    let gadget = params.gadget(
        DecompositionBaseLog::new(4),
        Some(DecompositionLevelCount::new(1)),
    );
    let crt_auto = crt_automorphism_key(&params, &gadget, &table);

    // A table can disagree with the gadget even when its key metadata is valid.
    let longer_table = UintDcrtTable::new(PolyLength::new(64), &q).unwrap();
    assert_eq!(
        CrtGlweAutoEvaluator::try_new(&crt_auto, &gadget, &longer_table).err(),
        Some(PolynomialLengthMismatch {
            expected: 32,
            actual: 64,
        })
    );
    let reversed_table = UintDcrtTable::new(n, &[q[1], q[0]]).unwrap();
    assert_eq!(
        CrtGlweAutoEvaluator::try_new(&crt_auto, &gadget, &reversed_table).err(),
        Some(ModulusOrderMismatch {
            index: 0,
            expected: 257,
            actual: 769,
        })
    );

    // Each gadget/table pair agrees internally, isolating the key's shared metadata check.
    for (n, dimension, q, radix, levels, expected) in [
        (
            64,
            1,
            &[257, 769][..],
            4,
            1,
            PolynomialLengthMismatch {
                expected: 32,
                actual: 64,
            },
        ),
        (
            32,
            2,
            &[257, 769][..],
            4,
            1,
            DimensionMismatch {
                expected: 1,
                actual: 2,
            },
        ),
        (
            32,
            1,
            &[257][..],
            4,
            1,
            ModuliCountMismatch {
                expected: 2,
                actual: 1,
            },
        ),
        (
            32,
            1,
            &[769, 257][..],
            4,
            1,
            ModulusOrderMismatch {
                index: 0,
                expected: 257,
                actual: 769,
            },
        ),
        (
            32,
            1,
            &[257, 1153][..],
            4,
            1,
            ModulusOrderMismatch {
                index: 1,
                expected: 769,
                actual: 1153,
            },
        ),
        (
            32,
            1,
            &[257, 769][..],
            5,
            1,
            DecompositionBaseLogMismatch {
                expected: 4,
                actual: 5,
            },
        ),
        (
            32,
            1,
            &[257, 769][..],
            4,
            2,
            DecompositionLevelCountMismatch {
                expected: 1,
                actual: 2,
            },
        ),
    ] {
        let moduli: Vec<_> = q.iter().copied().map(BarrettModulus::new).collect();
        let params = parameters(dimension, n, &moduli);
        let table = params.ntt_table();
        let gadget = params.gadget(
            DecompositionBaseLog::new(radix),
            Some(DecompositionLevelCount::new(levels)),
        );
        assert_eq!(
            CrtGlweAutoEvaluator::try_new(&crt_auto, &gadget, &table).err(),
            Some(expected),
            "N={n}, k={dimension}, Q={q:?}, radix={radix}, levels={levels}"
        );
    }
}

#[test]
fn trace_expansion_and_dcrt_automorphism_bindings_reject_wrong_radix() {
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, 32, &q);
    let table = params.ntt_table();
    let levels = Some(DecompositionLevelCount::new(1));
    let gadget = params.gadget(DecompositionBaseLog::new(4), levels);
    let sampling = params.encryption_parameters();
    let mut rng = StdRng::seed_from_u64(0x4155_544f);
    let (secret, dcrt_secret) = params.generate_key_pair(&table, &mut rng);
    // The other evaluators share the same validator. A wrong radix with the
    // same level count witnesses that each constructor checks the key metadata.
    let dcrt_auto = DcrtGlweAutoKey::new(&gadget, sampling, &table, 3, &dcrt_secret, &mut rng);
    let crt_trace =
        CrtGlweTraceKey::new(&gadget, sampling, &table, &secret, &dcrt_secret, &mut rng);
    let dcrt_trace = DcrtGlweTraceKey::new(&gadget, sampling, &table, &dcrt_secret, &mut rng);
    let reverse_trace = DcrtGlweRevTraceKey::new(&gadget, sampling, &table, &dcrt_secret, &mut rng);
    let crt_expand =
        CrtGlweExpandCoeffKey::new(&gadget, sampling, &table, &secret, &dcrt_secret, &mut rng);
    let dcrt_expand =
        DcrtGlweExpandCoeffKey::new(&gadget, sampling, &table, &dcrt_secret, &mut rng);
    let wrong_radix = params.gadget(DecompositionBaseLog::new(5), levels);
    for (name, result) in [
        (
            "DCRT auto",
            DcrtGlweAutoEvaluator::try_new(&dcrt_auto, &wrong_radix, &table).err(),
        ),
        (
            "CRT trace",
            CrtGlweTraceEvaluator::try_new(&crt_trace, &wrong_radix, &table).err(),
        ),
        (
            "DCRT trace",
            DcrtGlweTraceEvaluator::try_new(&dcrt_trace, &wrong_radix, &table).err(),
        ),
        (
            "reverse trace",
            DcrtGlweRevTraceEvaluator::try_new(&reverse_trace, &wrong_radix, &table).err(),
        ),
        (
            "CRT expand",
            CrtGlweExpandCoeffEvaluator::try_new(&crt_expand, &wrong_radix, &table).err(),
        ),
        (
            "DCRT expand",
            DcrtGlweExpandCoeffEvaluator::try_new(&dcrt_expand, &wrong_radix, &table).err(),
        ),
        (
            "CRT parallel",
            CrtGlweExpandCoeffParallelEvaluator::try_new(&crt_expand, &wrong_radix, &table, 2)
                .err(),
        ),
        (
            "DCRT parallel",
            DcrtGlweExpandCoeffParallelEvaluator::try_new(&dcrt_expand, &wrong_radix, &table, 2)
                .err(),
        ),
    ] {
        assert_eq!(
            result,
            Some(RnsDomainError::DecompositionBaseLogMismatch {
                expected: 4,
                actual: 5,
            }),
            "{name} must validate the key's radix"
        );
    }
}

/// Batch preparation must reject foreign secrets before its first RNG draw.
/// These are generation checks; evaluator radix/level rejection is covered above.
#[test]
fn automorphism_key_sets_reject_foreign_secrets_before_sampling() {
    use std::{
        fmt::Debug,
        panic::{AssertUnwindSafe, catch_unwind},
    };

    fn rejects_before_sampling(case: impl Debug, generate: impl FnOnce(&mut StdRng)) {
        let mut rejected = StdRng::seed_from_u64(4242);
        let mut untouched = StdRng::seed_from_u64(4242);
        let result = catch_unwind(AssertUnwindSafe(|| generate(&mut rejected)));
        assert!(result.is_err(), "{case:?}: foreign secret accepted");
        assert_eq!(
            rand::Rng::next_u64(&mut rejected),
            rand::Rng::next_u64(&mut untouched),
            "{case:?}: sampled before rejection"
        );
    }

    let n = PolyLength::new(32);
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, n.get(), &q);
    let table = params.ntt_table();
    let mut rng = StdRng::seed_from_u64(42);
    let (secret, dcrt_secret) = params.generate_key_pair(&table, &mut rng);
    let radix = DecompositionBaseLog::new(4);

    // Trace exercises both shared key-set generators. Only their foreign-key
    // check should fail because the supplied gadget, sampler and table agree.
    for (length, dimension, values) in [
        (64, 1, &[257, 769][..]),
        (32, 2, &[257, 769][..]),
        (32, 1, &[257][..]),
        (32, 1, &[769, 257][..]),
        (32, 1, &[257, 1153][..]),
    ] {
        let moduli: Vec<_> = values.iter().copied().map(BarrettModulus::new).collect();
        let foreign = parameters(dimension, length, &moduli);
        let foreign_table = foreign.ntt_table();
        let gadget = foreign.gadget(radix, None);
        let sampling = foreign.encryption_parameters();
        rejects_before_sampling(("CRT trace", length, dimension, values), |rng| {
            let _ = CrtGlweTraceKey::new(
                &gadget,
                sampling,
                &foreign_table,
                &secret,
                &dcrt_secret,
                rng,
            );
        });
        rejects_before_sampling(("DCRT trace", length, dimension, values), |rng| {
            let _ = DcrtGlweTraceKey::new(&gadget, sampling, &foreign_table, &dcrt_secret, rng);
        });
    }

    // Reversed limbs keep the layout identical while testing the remaining
    // DCRT entry points against an incompatible secret basis.
    let reversed = parameters(1, n.get(), &[q[1], q[0]]);
    let reversed_table = reversed.ntt_table();
    let reversed_gadget = reversed.gadget(radix, None);
    let reversed_sampling = reversed.encryption_parameters();
    rejects_before_sampling("reverse trace", |rng| {
        let _ = DcrtGlweRevTraceKey::new(
            &reversed_gadget,
            reversed_sampling,
            &reversed_table,
            &dcrt_secret,
            rng,
        );
    });
    rejects_before_sampling("DCRT expand", |rng| {
        let _ = DcrtGlweExpandCoeffKey::new(
            &reversed_gadget,
            reversed_sampling,
            &reversed_table,
            &dcrt_secret,
            rng,
        );
    });

    // CRT expansion reaches the coefficient-key guard with a valid DCRT key.
    let foreign = parameters(2, n.get(), &q);
    let foreign_secret =
        GlweSecretKey::generate(foreign.glwe_size(), foreign.secret_key_sampler(), &mut rng);
    let gadget = params.gadget(radix, None);
    rejects_before_sampling("CRT expand: foreign coefficient key", |rng| {
        let _ = CrtGlweExpandCoeffKey::new(
            &gadget,
            params.encryption_parameters(),
            &table,
            &foreign_secret,
            &dcrt_secret,
            rng,
        );
    });
}

#[test]
fn independent_sampling_and_table_inputs_reject_before_key_generation() {
    // Use the wide GLev domain. Matching dimensions and limb counts cannot
    // detect a table or sampler that presents the same primes in reverse order.
    let params = support::probe_parameters(3);
    let n = params.poly_length();
    let q = params.base_q().moduli();
    let table = params.ntt_table();
    let gadget = params.gadget(DecompositionBaseLog::new(20), None);
    let mut rng = StdRng::seed_from_u64(427);
    let (secret, dcrt_secret) = params.generate_key_pair(&table, &mut rng);
    let public_key = dcrt_secret
        .try_bind_raw(params.encryption_parameters(), params.base_q(), &table)
        .unwrap()
        .public_key(&mut rng);
    let reversed = [q[1], q[0]];
    let reversed_base = RNSBase::new(&reversed).unwrap();
    let sampling_for = |dimension, length, base: &RNSBase<u64, BarrettModulus<u64>>| {
        let size = GlweSize::new(GlweDimension::new(dimension), length);
        CrtGlweEncryptionParameters::try_new(
            RnsGlweSize::new(size, base.moduli_count()),
            base,
            SecretKeyDistr::SparseTernary,
            3.2,
        )
        .unwrap()
    };
    let longer = PolyLength::new(64);
    let longer_sampling = sampling_for(3, longer, params.base_q());
    let wider_sampling = sampling_for(4, n, params.base_q());
    let reversed_sampling = sampling_for(3, n, &reversed_base);
    let longer_table = UintDcrtTable::new(longer, q).unwrap();
    let reversed_table = UintDcrtTable::new(n, &reversed).unwrap();
    let wrong_length = RnsDomainError::PolynomialLengthMismatch {
        expected: n.get(),
        actual: longer.get(),
    };
    let order_mismatch = |expected, actual| RnsDomainError::ModulusOrderMismatch {
        index: 0,
        expected,
        actual,
    };
    let wrong_basis = order_mismatch(q[1].value(), q[0].value());
    let wrong_table_order = order_mismatch(q[0].value(), q[1].value());
    let wrong_dimension = RnsDomainError::DimensionMismatch {
        expected: 3,
        actual: 4,
    };
    let sampling = params.encryption_parameters();
    for (input, sampling, table, expected) in [
        ("sampler length", &longer_sampling, &table, &wrong_length),
        (
            "sampler dimension",
            &wider_sampling,
            &table,
            &wrong_dimension,
        ),
        ("sampler basis", &reversed_sampling, &table, &wrong_basis),
        ("table length", sampling, &longer_table, &wrong_length),
        ("table order", sampling, &reversed_table, &wrong_table_order),
    ] {
        assert_eq!(
            dcrt_secret
                .try_bind_gadget(&gadget, sampling, table)
                .err()
                .as_ref(),
            Some(expected),
            "secret gadget: {input}"
        );
        assert_eq!(
            public_key
                .try_bind_gadget(&gadget, sampling, table)
                .err()
                .as_ref(),
            Some(expected),
            "public gadget: {input}"
        );
        // Trace and expansion share one key-set generator per representation.
        // Exercise both before they can encrypt the first row.
        type Generator<'a> = (&'a str, &'a dyn Fn(&mut StdRng));
        let generators: [Generator<'_>; 2] = [
            ("CRT trace", &|rng| {
                let _ = CrtGlweTraceKey::new(&gadget, sampling, table, &secret, &dcrt_secret, rng);
            }),
            ("DCRT trace", &|rng| {
                let _ = DcrtGlweTraceKey::new(&gadget, sampling, table, &dcrt_secret, rng);
            }),
        ];
        for (operation, generate) in generators {
            let mut rejected = StdRng::seed_from_u64(428);
            let mut untouched = StdRng::seed_from_u64(428);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| generate(&mut rejected)))
                    .is_err(),
                "{operation}: accepted {input}"
            );
            assert_eq!(
                rand::Rng::next_u64(&mut rejected),
                rand::Rng::next_u64(&mut untouched),
                "{operation}: sampled before rejecting {input}"
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
    let table = parameters.ntt_table();
    let gadget = parameters.gadget(DecompositionBaseLog::new(4), None);
    let mut rng = StdRng::seed_from_u64(0x4c45_4e47_5448);
    let (secret, key) = parameters.generate_key_pair(&table, &mut rng);
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
