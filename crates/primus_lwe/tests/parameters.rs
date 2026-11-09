use primus_lattice::LweDimension;
use primus_lwe::{
    LweConfig, LweConfigError, LweEncryptionParameters, LweKeySwitchingParameters,
    LweParameterError, LweParameters, SecretKeyDistr,
};
use primus_modulus::{BarrettModulus, ModulusConfig, ModulusConfigError, NativeModulus};

/// Native/explicit pairing is checked once when binding the target to its basis.
#[test]
fn key_switching_basis_must_match_target_modulus() {
    use primus_decompose::{DecompositionBaseLog, primitive::ApproxSignedBasis};
    use primus_reduce::RingContext;

    fn check<M: RingContext<u64>>(modulus: M) {
        for basis_modulus in [None, Some(97), Some(101)] {
            let output = LweEncryptionParameters::new(
                LweDimension::new(3),
                modulus,
                SecretKeyDistr::UniformBinary,
                0.7,
            );
            let basis = ApproxSignedBasis::new(basis_modulus, DecompositionBaseLog::new(2), None);
            let result = LweKeySwitchingParameters::try_new(output, basis);
            if basis_modulus == modulus.explicit_value() {
                assert!(result.is_ok());
            } else {
                assert!(matches!(
                    result,
                    Err(LweParameterError::BasisModulusMismatch)
                ));
            }
        }
    }
    check(NativeModulus::new());
    check(BarrettModulus::new(97));
}

/// Config preparation distinguishes reducer selection from prepared-sampler errors.
#[test]
fn config_reports_modulus_and_sampler_errors() {
    let config = LweConfig::<NativeModulus<u64>> {
        dimension: LweDimension::new(4),
        cipher_modulus: ModulusConfig::Native,
        secret_key_distr: SecretKeyDistr::UniformBinary,
        noise_standard_deviation: 0.7,
    };
    assert!(matches!(
        LweEncryptionParameters::try_from(LweConfig {
            cipher_modulus: ModulusConfig::Explicit(1024),
            ..config
        }),
        Err(LweConfigError::Modulus(ModulusConfigError::Native))
    ));
    assert!(matches!(
        LweEncryptionParameters::try_from(LweConfig {
            noise_standard_deviation: 0.0,
            ..config
        }),
        Err(LweConfigError::Parameters(LweParameterError::Noise(_)))
    ));
    assert!(matches!(
        LweEncryptionParameters::try_from(LweConfig {
            secret_key_distr: SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 5 },
            ..config
        }),
        Err(LweConfigError::Parameters(LweParameterError::SecretKey(_)))
    ));
}

#[test]
fn secret_support_is_checked_at_parameter_construction() {
    for (sigma, valid) in [(1.0, true), (1.1, false)] {
        // With q = 13, truncated magnitudes 12 and 13 straddle the bound.
        let result = std::panic::catch_unwind(|| {
            LweParameters::new(
                LweDimension::new(16),
                2u32,
                BarrettModulus::new(13),
                SecretKeyDistr::gaussian(sigma),
                0.7,
            )
        });
        assert_eq!(result.is_ok(), valid);
    }
}

#[test]
fn fallible_parameters_report_encoding_noise_and_secret_errors() {
    use primus_lwe::LweParameterError as Error;
    let make = |t, distr, noise| {
        LweParameters::try_new(
            LweDimension::new(4),
            t,
            NativeModulus::<u32>::new(),
            distr,
            noise,
        )
    };
    assert!(matches!(
        make(1, SecretKeyDistr::UniformBinary, 0.7),
        Err(Error::Encoding(_))
    ));
    for noise in [0.0, f64::INFINITY, f64::NAN] {
        assert!(matches!(
            make(4, SecretKeyDistr::UniformBinary, noise),
            Err(Error::Noise(_))
        ));
    }
    for distr in [
        SecretKeyDistr::Binary {
            one_probability: -1.0,
        },
        SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 5 },
    ] {
        assert!(matches!(make(4, distr, 0.7), Err(Error::SecretKey(_))));
    }
    assert_eq!(
        LweParameters::try_new(
            LweDimension::new(4),
            2,
            BarrettModulus::new(13u32),
            SecretKeyDistr::gaussian(1.1),
            0.7
        )
        .err(),
        Some(Error::SecretKey(
            primus_distr::SecretKeySamplerError::ModulusTooSmall {
                maximum_magnitude: 13,
                modulus_minus_one: 12,
            }
        ))
    );
}
