use primus_bfv::{BfvParameters, BfvParametersError};
use primus_distr::ErrorDistribution;
use primus_encoding::{BfvRnsCodecError, PlaintextEmbedding};
use primus_glwe_rns::{CrtGlweEncryptionParametersError, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_rns::RnsError;
use primus_shape::PolyLength;
use std::error::Error;

#[test]
fn parameter_errors_keep_their_own_sources() {
    let construct = |moduli: &[BarrettModulus<u64>], gamma, sigma| {
        BfvParameters::try_new(
            PolyLength::new(32),
            BarrettModulus::new(3),
            BarrettModulus::new(gamma),
            moduli,
            SecretKeyDistr::SparseTernary,
            sigma,
        )
    };
    assert!(matches!(
        construct(&[], 101, 1.0),
        Err(BfvParametersError::RnsBase(RnsError::EmptyBase))
    ));
    assert!(matches!(
        construct(&[BarrettModulus::new(97); 2], 101, 1.0),
        Err(BfvParametersError::RnsBase(RnsError::NonCoprimeModuli))
    ));
    assert!(matches!(
        construct(&[97, 17].map(BarrettModulus::new), 7, 1.0),
        Err(BfvParametersError::Encoding(
            BfvRnsCodecError::AuxiliaryModulusTooSmall {
                gamma: 7,
                lower_bound: 8
            }
        ))
    ));
    let error = construct(&[BarrettModulus::new(97)], 101, f64::NAN)
        .err()
        .unwrap();
    assert!(matches!(
        &error,
        BfvParametersError::Encryption(CrtGlweEncryptionParametersError::ErrorSampler(
            primus_distr::ErrorSamplerError::Gaussian(_)
        ))
    ));
    let mut source: &(dyn Error + 'static) = &error;
    let mut gaussian_reason = false;
    while let Some(next) = source.source() {
        gaussian_reason |= next.downcast_ref::<primus_distr::GaussianError>().is_some();
        source = next;
    }
    assert!(gaussian_reason);
}

#[test]
fn explicit_cbd_law_is_preserved() {
    let parameters = BfvParameters::try_with_error_distribution(
        PolyLength::new(32),
        BarrettModulus::new(3),
        BarrettModulus::new(101),
        &[97, 193].map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::CenteredBinomial { eta: 21 },
    )
    .unwrap();
    assert_eq!(
        parameters
            .encryption_parameters()
            .noise_distribution()
            .distribution(),
        ErrorDistribution::CenteredBinomial { eta: 21 }
    );
    assert_eq!(
        parameters
            .encryption_parameters()
            .noise_distribution()
            .maximum_magnitude(),
        21
    );
}

#[test]
fn constructors_check_complete_private_noise_recovery() {
    let moduli = [BarrettModulus::new(97u64)];
    for (gamma, sigma, magnitude, valid) in [
        (13, 1.0, 12, true),
        (13, 1.25, 15, false),
        (101, 1.25, 15, true),
        (101, 1.375, 16, false),
    ] {
        let result = BfvParameters::try_new(
            PolyLength::new(32),
            BarrettModulus::new(3),
            BarrettModulus::new(gamma),
            &moduli,
            SecretKeyDistr::UniformBinary,
            sigma,
        );
        if valid {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(BfvParametersError::Encoding(
                BfvRnsCodecError::InsufficientNoiseRecovery {
                    maximum_noise_magnitude,
                    embedding: PlaintextEmbedding::Unsigned,
                }
            )) if maximum_noise_magnitude == magnitude));
        }
    }
}
