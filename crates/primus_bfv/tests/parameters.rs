use primus_bfv::{BfvParameters, BfvParametersError};
use primus_distr::ErrorDistribution;
use primus_encoding::{BfvRnsCodecError, PlaintextEmbedding};
use primus_glwe_rns::{
    CrtGlweEncryptionParametersError, SecretKeyDistr, rlwe_parameters::RlweParameterError,
};
use primus_modulus::BarrettModulus;
use primus_rns::RnsError;
use primus_shape::PolyLength;
use std::error::Error;

#[test]
fn parameter_errors_keep_their_own_sources() {
    let construct = |moduli: &[BarrettModulus<u64>], gamma, sigma| {
        BfvParameters::try_with_decoder_modulus(
            PolyLength::new(32),
            BarrettModulus::new(3),
            BarrettModulus::new(gamma),
            moduli,
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::Gaussian {
                standard_deviation: sigma,
            },
        )
    };
    assert!(matches!(
        construct(&[], 101, 1.0),
        Err(BfvParametersError::RnsBase(RnsError::EmptyBase))
    ));
    assert!(matches!(
        construct(&[BarrettModulus::new(193); 2], 101, 1.0),
        Err(BfvParametersError::RnsBase(RnsError::NonCoprimeModuli))
    ));
    assert!(matches!(
        construct(&[193, 257].map(BarrettModulus::new), 7, 1.0),
        Err(BfvParametersError::Encoding(
            BfvRnsCodecError::AuxiliaryModulusTooSmall {
                gamma: 7,
                lower_bound: 8
            }
        ))
    ));
    assert!(matches!(
        construct(&[BarrettModulus::new(49_601)], 101, 1.0),
        Err(BfvParametersError::PrimeBasis(
            RlweParameterError::NotPrime { modulus: 49_601 }
        ))
    ));
    assert!(matches!(
        construct(&[BarrettModulus::new(97)], 101, 1.0),
        Err(BfvParametersError::PrimeBasis(
            RlweParameterError::NttOrder {
                modulus: 97,
                order: 64
            }
        ))
    ));
    let error = construct(&[BarrettModulus::new(193)], 101, f64::NAN)
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
    let parameters = BfvParameters::try_with_decoder_modulus(
        PolyLength::new(32),
        BarrettModulus::new(3),
        BarrettModulus::new(101),
        &[193, 257].map(BarrettModulus::new),
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
    let moduli = [BarrettModulus::new(193u64)];
    for (gamma, sigma, magnitude, valid) in [
        (13, 2.1875, 26, true),
        (13, 2.25, 27, false),
        (101, 2.5, 30, true),
        (101, 2.625, 31, false),
    ] {
        let result = BfvParameters::try_with_decoder_modulus(
            PolyLength::new(32),
            BarrettModulus::new(3),
            BarrettModulus::new(gamma),
            &moduli,
            SecretKeyDistr::UniformBinary,
            ErrorDistribution::Gaussian {
                standard_deviation: sigma,
            },
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
