use primus_distr::ErrorDistribution;
use primus_glwe_rns::{
    CrtGlweEncryptionParameters, SecretKeyDistr,
    rlwe_parameters::{
        RlweParameterError, RlweSecurityStatus, search_ntt_primes, security_input,
        validate_ntt_primes,
    },
};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_rns::RNSBase;
use primus_shape::PolyLength;

fn sampling(
    dimension: usize,
    secret: SecretKeyDistr,
    error: ErrorDistribution,
) -> CrtGlweEncryptionParameters<u64> {
    let moduli = [BarrettModulus::new(449u64)];
    let base = RNSBase::new(&moduli).unwrap();
    let size = RnsGlweSize::new(
        GlweSize::new(GlweDimension::new(dimension), PolyLength::new(32)),
        base.moduli_count(),
    );
    CrtGlweEncryptionParameters::try_with_error_distribution(size, &base, secret, error).unwrap()
}

#[test]
fn explicit_prime_validation_owns_the_kernel_boundary() {
    validate_ntt_primes(32, &[193, 257, 449]).unwrap();
    assert!(matches!(
        validate_ntt_primes(32, &[]),
        Err(RlweParameterError::EmptyBasis)
    ));
    assert!(matches!(
        validate_ntt_primes(32, &[65]),
        Err(RlweParameterError::NotPrime { modulus: 65 })
    ));
    assert!(matches!(
        validate_ntt_primes(32, &[97]),
        Err(RlweParameterError::NttOrder { modulus: 97, .. })
    ));
    assert!(matches!(
        validate_ntt_primes(32, &[193, 193]),
        Err(RlweParameterError::DuplicatePrime { modulus: 193 })
    ));
    assert!(matches!(
        validate_ntt_primes(32, &[1 << 62]),
        Err(RlweParameterError::ModulusTooLarge { .. })
    ));
    assert!(matches!(
        validate_ntt_primes(33, &[193]),
        Err(RlweParameterError::PolyLength(_))
    ));
}

#[test]
fn bounded_search_preserves_width_plaintext_progression_and_exclusions() {
    let first = search_ntt_primes(32, 20, 4, Some(17), &[]).unwrap();
    let next = search_ntt_primes(32, 20, 3, Some(17), &first).unwrap();
    for &prime in first.iter().chain(&next) {
        assert_eq!(prime.ilog2() + 1, 20);
        assert_eq!(prime % (64 * 17), 1);
        // Independent trial division is cheap at this small test width.
        assert!(
            !(2..)
                .take_while(|d| d * d <= prime)
                .any(|d| prime.is_multiple_of(d))
        );
    }
    assert!(first.windows(2).all(|pair| pair[0] > pair[1]));
    assert!(next.iter().all(|p| !first.contains(p)));
    for (bits, count, congruence) in [(1, 1, None), (20, 0, None), (20, 1, Some(0))] {
        assert!(matches!(
            search_ntt_primes(32, bits, count, congruence, &[]),
            Err(RlweParameterError::SearchRequest)
        ));
    }
    assert!(matches!(
        search_ntt_primes(32, 6, 1, None, &[]),
        Err(RlweParameterError::SearchExhausted { .. })
    ));
    assert!(matches!(
        search_ntt_primes(32, 20, 1, Some(u64::MAX), &[]),
        Err(RlweParameterError::SearchRequest)
    ));
}

#[test]
fn security_inventory_reports_actual_key_domain_without_a_security_verdict() {
    let secret = SecretKeyDistr::SparseTernary;
    let error = ErrorDistribution::CenteredBinomial { eta: 21 };
    let sampling = sampling(1, secret, error);
    let q = security_input(&sampling, &[193, 257], &[]).unwrap();
    let qp = security_input(&sampling, &[193, 257], &[449]).unwrap();
    assert_eq!(q.modulus_words, [193 * 257]);
    assert_eq!(qp.modulus_words, [22_270_849]);
    assert_eq!(qp.modulus_bits, 25);
    assert_eq!(qp.data_moduli, [193, 257]);
    assert_eq!(qp.key_auxiliary_moduli, [449]);
    assert_eq!(qp.secret_maximum_magnitude, 1);
    assert_eq!(qp.error_maximum_magnitude, 21);
    assert_eq!(qp.secret_distribution, secret);
    assert_eq!(qp.error_distribution, error);
    assert_eq!(qp.status, RlweSecurityStatus::NotEvaluated);
    assert_eq!(qp.ephemeral_distribution, None);
    assert!(matches!(
        security_input(&sampling, &[193, 257], &[257]),
        Err(RlweParameterError::DuplicatePrime { .. })
    ));
    let wide = security_input(
        &sampling,
        &[1152921422732787713, 1152921409847689217],
        &[1152921396962590721],
    )
    .unwrap();
    // Independently expanded 180-bit integer product, exceeding u128.
    assert_eq!(
        wide.modulus_words,
        [2701110158619967489, 13250921771164281051, 4503598516911706]
    );
    assert_eq!(wide.modulus_bits, 180);
}

#[test]
fn security_inventory_reuses_prepared_support_and_rejects_glwe_rank() {
    let secret = SecretKeyDistr::SparseTernary;
    let error = ErrorDistribution::CenteredBinomial { eta: 21 };
    let glwe = sampling(2, secret, error);
    assert!(matches!(
        security_input(&glwe, &[193], &[]),
        Err(RlweParameterError::Rank { dimension: 2 })
    ));
    let gaussian_secret = sampling(
        1,
        SecretKeyDistr::Gaussian {
            standard_deviation: 20.0,
        },
        error,
    );
    assert!(matches!(
        security_input(&gaussian_secret, &[193], &[]),
        Err(RlweParameterError::SecretSampler(_))
    ));
    let gaussian_error = sampling(
        1,
        secret,
        ErrorDistribution::Gaussian {
            standard_deviation: 20.0,
        },
    );
    assert!(matches!(
        security_input(&gaussian_error, &[193], &[]),
        Err(RlweParameterError::ErrorSampler(_))
    ));
}
