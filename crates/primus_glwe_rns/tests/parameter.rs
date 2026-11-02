mod support;

use primus_decompose::{ApproxSignedBasisError, big_integer::BigUintApproxSignedBasis};
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlevParametersError, CrtGlweEncryptionParameters,
    CrtGlweEncryptionParametersError, DcrtGadgetDomain, RnsDomainError, SecretKeyDistr,
};
use primus_integer::BigUint;
use primus_lattice::{GlweDimension, GlweSize, GlweSizeError, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_rns::RNSBase;
use primus_shape::PolyLength;
use std::sync::Arc;

#[test]
fn noise_support_must_fit_every_rns_modulus() {
    let moduli = [97u64, 17].map(BarrettModulus::new);
    let base_q = RNSBase::new(&moduli).unwrap();
    // Bounds 16, 17, 18 exercise strict comparison against the second modulus.
    for (sigma, magnitude, valid) in [(1.375, 16, true), (1.4375, 17, false), (1.5, 18, false)] {
        assert_eq!(
            primus_distr::SignedDiscreteGaussian::<i64>::new(sigma)
                .unwrap()
                .maximum_magnitude(),
            magnitude
        );
        let result = CrtGlweEncryptionParameters::try_new(
            RnsGlweSize::new(
                GlweSize::new(GlweDimension::new(1), PolyLength::new(32)),
                base_q.moduli_count(),
            ),
            &base_q,
            SecretKeyDistr::UniformBinary,
            sigma,
        );
        if valid {
            assert!(result.is_ok());
        } else {
            assert!(
                matches!(result, Err(CrtGlweEncryptionParametersError::ErrorSampler(
                primus_distr::ErrorSamplerError::ModulusTooSmall { maximum_magnitude, modulus_minus_one: 16 }
            )) if maximum_magnitude == magnitude)
            );
        }
    }
}

#[test]
fn secret_support_must_fit_every_rns_modulus() {
    let moduli = [97u64, 17].map(BarrettModulus::new);
    let base_q = RNSBase::new(&moduli).unwrap();
    for (sigma, valid) in [(1.0, true), (1.5, false)] {
        let result = CrtGlweEncryptionParameters::try_new(
            RnsGlweSize::new(
                GlweSize::new(GlweDimension::new(1), PolyLength::new(32)),
                base_q.moduli_count(),
            ),
            &base_q,
            SecretKeyDistr::gaussian(sigma),
            0.7,
        );
        if valid {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(CrtGlweEncryptionParametersError::SecretKey(
                    primus_distr::SecretKeySamplerError::ModulusTooSmall {
                        modulus_minus_one: 16,
                        ..
                    }
                ))
            ));
        }
    }
}

#[test]
fn explicit_error_distributions_keep_codec_free_bounds_and_auxiliary_bases() {
    use primus_distr::{CenteredBinomialError, ErrorDistribution, ErrorSamplerError};
    use rand::{SeedableRng, rngs::StdRng};

    let moduli = [97_u32, 193].map(BarrettModulus::new);
    let base_q = RNSBase::new(&moduli).unwrap();
    const N: usize = 32;
    let size = RnsGlweSize::new(GlweSize::new(GlweDimension::new(2), PolyLength::new(N)), 2);
    let construct = |error| {
        CrtGlweEncryptionParameters::try_with_error_distribution(
            size,
            &base_q,
            SecretKeyDistr::SparseTernary,
            error,
        )
    };
    assert!(matches!(
        construct(ErrorDistribution::CenteredBinomial { eta: 0 }),
        Err(CrtGlweEncryptionParametersError::ErrorSampler(
            ErrorSamplerError::CenteredBinomial(CenteredBinomialError::InvalidEta { eta: 0 })
        ))
    ));
    let core = construct(ErrorDistribution::CenteredBinomial { eta: 21 }).unwrap();
    assert_eq!(core.noise_distribution().maximum_magnitude(), 21);
    // A Q core can sample the same integer into a checked QP auxiliary basis.
    // It must use the provided count, rather than truncating to its two Q limbs.
    let qp = [97, 193, 257];
    let mut output = vec![u32::MAX; 3 * N];
    core.sample_noise_to(&mut output, &qp, &mut StdRng::seed_from_u64(507));
    for coefficient in 0..N {
        let residue = i64::from(output[coefficient]);
        let signed = if residue > 97 / 2 {
            residue - 97
        } else {
            residue
        };
        assert!(signed.abs() <= 21);
        for (index, modulus) in qp.iter().enumerate() {
            assert_eq!(
                i64::from(output[index * N + coefficient]),
                signed.rem_euclid(i64::from(*modulus))
            );
        }
    }

    let small_base = RNSBase::new(&[97_u32, 17].map(BarrettModulus::new)).unwrap();
    assert!(matches!(
        CrtGlweEncryptionParameters::try_with_error_distribution(
            size,
            &small_base,
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 21 },
        ),
        Err(CrtGlweEncryptionParametersError::ErrorSampler(
            ErrorSamplerError::ModulusTooSmall {
                maximum_magnitude: 21,
                modulus_minus_one: 16,
            }
        ))
    ));
}

#[test]
fn sampling_errors_retain_their_real_source() {
    use std::error::Error;
    let base = RNSBase::new(&[BarrettModulus::new(97_u32)]).unwrap();
    let error = CrtGlweEncryptionParameters::try_new(
        RnsGlweSize::new(GlweSize::new(GlweDimension::new(1), PolyLength::new(32)), 1),
        &base,
        SecretKeyDistr::SparseTernary,
        f64::NAN,
    )
    .err()
    .expect("NaN scale must fail sampling preparation");
    assert!(matches!(
        &error,
        CrtGlweEncryptionParametersError::ErrorSampler(primus_distr::ErrorSamplerError::Gaussian(
            _
        ))
    ));
    let mut current: &(dyn Error + 'static) = &error;
    let mut found = false;
    while let Some(source) = current.source() {
        found |= source
            .downcast_ref::<primus_distr::GaussianError>()
            .is_some();
        current = source;
    }
    assert!(
        found,
        "Gaussian construction reason must remain in the source chain"
    );
}

// The logical key has kN=64 coefficients, despite 128 stored RNS residues.
#[test]
fn fixed_secret_weights_are_checked_against_the_complete_logical_key() {
    let moduli = [97u32, 17].map(BarrettModulus::new);
    let base_q = RNSBase::new(&moduli).unwrap();
    for (distribution, valid) in [
        (
            SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 64 },
            true,
        ),
        (
            SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 65 },
            false,
        ),
        (
            SecretKeyDistr::FixedHammingWeightTernary { hamming_weight: 64 },
            true,
        ),
        (
            SecretKeyDistr::FixedHammingWeightTernary { hamming_weight: 65 },
            false,
        ),
        (
            SecretKeyDistr::FixedCompositionTernary {
                negative_one_weight: 32,
                one_weight: 32,
            },
            true,
        ),
        (
            SecretKeyDistr::FixedCompositionTernary {
                negative_one_weight: 33,
                one_weight: 32,
            },
            false,
        ),
        (
            SecretKeyDistr::FixedCompositionTernary {
                negative_one_weight: usize::MAX,
                one_weight: 1,
            },
            false,
        ),
    ] {
        let result = CrtGlweEncryptionParameters::try_new(
            RnsGlweSize::new(
                GlweSize::new(GlweDimension::new(2), PolyLength::new(32)),
                base_q.moduli_count(),
            ),
            &base_q,
            distribution,
            1.0,
        );
        if valid {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(CrtGlweEncryptionParametersError::SecretKey(
                    primus_distr::SecretKeySamplerError::InvalidWeight { length: 64 }
                ))
            ));
        }
    }
}

#[test]
fn gadget_parameters_check_basis_and_composed_lengths() {
    // The restrictive modulus is deliberately not the first one.
    let moduli = [97u64, 17].map(BarrettModulus::new);
    let glwe = support::RawParameters::new(
        GlweDimension::new(1),
        PolyLength::new(32),
        &moduli,
        SecretKeyDistr::UniformTernary,
        1.0,
    );
    assert!(
        CrtGlevParameters::try_new(
            Arc::clone(&glwe.core),
            glwe.base.clone(),
            DecompositionBaseLog::new(4),
            None
        )
        .is_ok()
    );
    for log_basis in [5, 6] {
        assert!(matches!(
            CrtGlevParameters::try_new(Arc::clone(&glwe.core), glwe.base.clone(), DecompositionBaseLog::new(log_basis), None),
            Err(CrtGlevParametersError::BasisNotSmallerThanModulus { basis, modulus: 17, index: 1 })
                if basis == 1 << log_basis
        ));
    }
    assert!(matches!(
        CrtGlevParameters::try_new(
            Arc::clone(&glwe.core),
            glwe.base.clone(),
            DecompositionBaseLog::new(64),
            None
        ),
        Err(CrtGlevParametersError::InvalidDecomposition(
            ApproxSignedBasisError::InvalidLogBasis { .. }
        ))
    ));

    // Parameters store sizes without allocating ciphertexts. This ordinary
    // RNS layout fits, while its two-level gadget storage does not.
    let large_layout = support::RawParameters::new(
        GlweDimension::new(usize::MAX / 64 - 1),
        PolyLength::new(32),
        &moduli,
        SecretKeyDistr::UniformTernary,
        1.0,
    );
    assert!(matches!(
        CrtGlevParameters::try_new(
            Arc::clone(&large_layout.core),
            large_layout.base.clone(),
            DecompositionBaseLog::new(4),
            None
        ),
        Err(CrtGlevParametersError::Layout(
            GlweSizeError::LengthOverflow("RNS GLev ciphertext")
        ))
    ));
}

#[test]
fn prepared_parts_require_the_same_ordered_base_and_product() {
    let moduli = [97u32, 17].map(BarrettModulus::new);
    let base_q = RNSBase::new(&moduli).unwrap();
    let glwe_size = GlweSize::new(GlweDimension::new(1), PolyLength::new(32));
    assert!(matches!(
        CrtGlweEncryptionParameters::try_new(
            RnsGlweSize::new(glwe_size, 3),
            &base_q,
            SecretKeyDistr::UniformBinary,
            1.0,
        ),
        Err(CrtGlweEncryptionParametersError::Domain(
            RnsDomainError::ModuliCountMismatch {
                expected: 3,
                actual: 2,
            }
        ))
    ));
    let inner = Arc::new(CrtGlweEncryptionParameters::new(
        RnsGlweSize::new(glwe_size, 2),
        &base_q,
        SecretKeyDistr::UniformBinary,
        1.0,
    ));
    let basis = || {
        BigUintApproxSignedBasis::new(base_q.moduli_product(), DecompositionBaseLog::new(4), None)
    };

    // Equal products, equal limb counts and valid individual bases do not prove
    // that their samplers/decomposition buffers use the same ordered Q.
    for values in [&[17, 97][..], &[97, 19], &[97]] {
        let foreign = RNSBase::new(
            &values
                .iter()
                .copied()
                .map(BarrettModulus::new)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(matches!(
            CrtGlevParameters::try_from_parts(Arc::clone(&inner), foreign.clone(), basis()),
            Err(CrtGlevParametersError::Domain(_))
        ));
    }
    for modulus in [&[97 * 17 + 1][..], &[97 * 17, 1]] {
        let foreign_basis =
            BigUintApproxSignedBasis::new(BigUint(modulus), DecompositionBaseLog::new(4), None);
        assert!(matches!(
            CrtGlevParameters::try_from_parts(Arc::clone(&inner), base_q.clone(), foreign_basis),
            Err(CrtGlevParametersError::BasisModulusMismatch)
        ));
    }

    let gadget =
        CrtGlevParameters::try_from_parts(Arc::clone(&inner), base_q.clone(), basis()).unwrap();
    let derived = CrtGlevParameters::new(
        Arc::clone(&inner),
        base_q.clone(),
        DecompositionBaseLog::new(3),
        None,
    );
    for params in [&gadget, &derived, &gadget.clone()] {
        assert!(std::ptr::eq(inner.as_ref(), params.encryption_parameters()));
        assert!(std::ptr::eq(
            base_q.moduli_product().0,
            params.base_q().moduli_product().0
        ));
        assert!(std::ptr::eq(
            inner.noise_distribution(),
            params.noise_distribution()
        ));
    }
}

#[test]
fn cached_weights_and_centered_digits_follow_rns_order() {
    let moduli = [134_215_681u32, 134_176_769];
    let q: u64 = moduli.iter().map(|&modulus| u64::from(modulus)).product();
    let glwe = support::RawParameters::new(
        GlweDimension::new(1),
        PolyLength::new(32),
        &moduli.map(BarrettModulus::new),
        SecretKeyDistr::UniformTernary,
        1.0,
    );
    // Two-limb values, including centered boundaries and a SIMD tail.
    let values: Vec<u32> = [0, 1, q / 2, q - 1]
        .into_iter()
        .chain((1..=13).map(|index| index * (q / 17)))
        .flat_map(|value| [value as u32, (value >> 32) as u32])
        .collect();
    let count = values.len() / 2;
    for (log_basis, retained) in [(3, None), (5, Some(2))] {
        let params = glwe.gadget(
            DecompositionBaseLog::new(log_basis),
            retained.map(DecompositionLevelCount::new),
        );
        let basis = params.basis();
        assert_eq!(
            params.scalar_residue_iter().len(),
            basis.level_count().get()
        );
        for (level, residues) in params.scalar_residue_iter().enumerate() {
            let weight = 1u64 << (basis.drop_bits() + level as u32 * log_basis);
            assert_eq!(
                residues.as_ref(),
                moduli.map(|modulus| (weight % u64::from(modulus)) as u32)
            );
        }

        let mut adjusted = vec![0; values.len()];
        let mut carries = vec![false; count];
        basis.init_value_carry_slice_to(&values, &mut adjusted, &mut carries);
        let mut signed_digits = vec![0; values.len()];
        let mut unsigned_digits = vec![0; count];
        let mut residues = vec![0; count * moduli.len()];
        for decomposer in basis.decomposer_iter() {
            let mut unsigned_carries = carries.clone();
            decomposer.decompose_slice_to(&adjusted, &mut signed_digits, &mut carries);
            decomposer.decompose_radix_slice_to(
                &adjusted,
                &mut unsigned_digits,
                &mut unsigned_carries,
            );
            assert_eq!(carries, unsigned_carries);
            params.base_q().wrapping_decompose_small_values_to(
                &unsigned_digits,
                &mut residues,
                basis.basis_value(),
            );
            // Lifted digits are modulus-major, while full-width digits are value-major.
            for (&modulus, chunk) in moduli.iter().zip(residues.chunks_exact(count)) {
                for (&residue, digit) in chunk.iter().zip(signed_digits.as_chunks::<2>().0) {
                    let digit = u64::from(digit[0]) | (u64::from(digit[1]) << 32);
                    assert_eq!(u64::from(residue), digit % u64::from(modulus));
                }
            }
        }
    }
}

// Equal limb counts and lengths do not imply equal ordered evaluation domains.
#[test]
fn domain_rejects_modulus_order_mismatch() {
    let moduli_values = [1_125_899_906_826_241u64, 1_125_899_906_629_633];
    let moduli = moduli_values.map(BarrettModulus::new);
    let crt_glwe = support::RawParameters::new(
        GlweDimension::new(1),
        PolyLength::new(32),
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.2,
    );
    let crt_gadget = crt_glwe.gadget(DecompositionBaseLog::new(20), None);
    let reversed = [moduli[1], moduli[0]];
    let wrong_order_table = UintDcrtTable::new(PolyLength::new(32), &reversed).unwrap();
    assert!(matches!(
        DcrtGadgetDomain::try_new(&crt_gadget, &wrong_order_table),
        Err(RnsDomainError::ModulusOrderMismatch { index: 0, .. })
    ));
}
