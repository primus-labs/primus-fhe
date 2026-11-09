use std::fmt::Debug;

use primus_distr::{
    CDTSampler, DiscreteGaussian, DiscreteZiggurat, GaussianError, SignedCDTSampler,
    SignedDiscreteGaussian, SignedDiscreteZiggurat,
};
use rand::{Rng, SeedableRng, distr::Distribution, rngs::StdRng};

/// Compare allocation and destination APIs with scalar sampling, including the next RNG word.
fn check_batch<T: Clone + Default + Debug + PartialEq, D: Distribution<T>>(
    distr: &D,
    length: usize,
    sample_vec: impl FnOnce(&D, usize, &mut StdRng) -> Vec<T>,
    sample_to: impl FnOnce(&D, &mut [T], &mut StdRng),
) {
    let mut rng = StdRng::seed_from_u64(501);
    let expected: Vec<T> = distr.sample_iter(&mut rng).take(length).collect();
    let expected_next = rng.next_u64();

    let mut rng = StdRng::seed_from_u64(501);
    assert_eq!(sample_vec(distr, length, &mut rng), expected);
    assert_eq!(rng.next_u64(), expected_next);

    let mut output = vec![T::default(); length];
    let mut rng = StdRng::seed_from_u64(501);
    sample_to(distr, &mut output, &mut rng);
    assert_eq!(output, expected);
    assert_eq!(rng.next_u64(), expected_next);
}

/// Explicit backend wrappers must report their supplied tail cut, not the facade default.
#[test]
fn signed_support_bound_preserves_custom_backend_tail_cuts() {
    let cdt = SignedDiscreteGaussian::Cdt(SignedCDTSampler::<i32>::new(3.2, 8.0).unwrap());
    let ziggurat =
        SignedDiscreteGaussian::Ziggurat(SignedDiscreteZiggurat::<i32>::new(30.0, 8.0).unwrap());
    assert_eq!(cdt.maximum_magnitude(), 25);
    assert_eq!(ziggurat.maximum_magnitude(), 240);
}

/// A converged layer table may still exceed a short tail's declared integer support.
#[test]
fn ziggurat_rejects_layers_outside_declared_support() {
    for (sigma, tail_cut, maximum_magnitude) in
        [(30.0, 0.5, 15u32), (100.0, 0.02, 2), (10.0, 3.0, 30)]
    {
        assert!(matches!(
            SignedDiscreteZiggurat::<i32>::new(sigma, tail_cut),
            Err(GaussianError::ZigguratConstructionFailed { .. })
        ));
        // Test both the smallest encodable modulus and a wider output range:
        // rejecting invalid layers must not depend on the adapter's capacity.
        for modulus_minus_one in [maximum_magnitude, u32::MAX] {
            assert!(matches!(
                DiscreteZiggurat::new(sigma, tail_cut, modulus_minus_one),
                Err(GaussianError::ZigguratConstructionFailed { .. })
            ));
        }
        // The short tails themselves are valid; this restriction is specific
        // to Ziggurat layers, not the shared Gaussian parameter domain.
        assert!(SignedCDTSampler::<i32>::new(sigma, tail_cut).is_ok());
        assert!(CDTSampler::new(sigma, tail_cut, maximum_magnitude).is_ok());
    }
}

/// Signed/modular adapters and facade selection retain the same samples and RNG stream.
#[test]
fn ziggurat_default_adapters_preserve_support_and_encoding() {
    // Include the current large LWE noise and a support beyond f64's consecutive
    // integer range; the bound is always the original integer magnitude.
    for (sigma, maximum_magnitude) in [
        (30.0, 360u64),
        (2_303_762_004.981_150_6, 27_645_144_059),
        ((1u64 << 53) as f64, 108_086_391_056_891_904),
    ] {
        let signed = SignedDiscreteZiggurat::<i64>::new(sigma, 12.0).unwrap();
        let facade = SignedDiscreteGaussian::<i64>::new(sigma).unwrap();
        assert!(matches!(facade, SignedDiscreteGaussian::Ziggurat(_)));
        assert_eq!(facade.maximum_magnitude(), maximum_magnitude);
        for modulus_minus_one in [maximum_magnitude, u64::MAX] {
            let encoded = DiscreteZiggurat::new(sigma, 12.0, modulus_minus_one).unwrap();
            let encoded_facade = DiscreteGaussian::new(sigma, modulus_minus_one).unwrap();
            assert!(matches!(encoded_facade, DiscreteGaussian::Ziggurat(_)));
            let mut signed_rng = StdRng::seed_from_u64(501);
            let mut facade_rng = StdRng::seed_from_u64(501);
            let mut encoded_rng = StdRng::seed_from_u64(501);
            let mut encoded_facade_rng = StdRng::seed_from_u64(501);
            for _ in 0..16 {
                let value = signed.sample(&mut signed_rng);
                assert!(value.unsigned_abs() <= maximum_magnitude);
                assert_eq!(facade.sample(&mut facade_rng), value);
                let expected = if value < 0 {
                    modulus_minus_one - value.unsigned_abs() + 1
                } else {
                    value as u64
                };
                assert!(expected <= modulus_minus_one);
                assert_eq!(encoded.sample(&mut encoded_rng), expected);
                assert_eq!(encoded_facade.sample(&mut encoded_facade_rng), expected);
            }
            let next = signed_rng.next_u64();
            assert_eq!(facade_rng.next_u64(), next);
            assert_eq!(encoded_rng.next_u64(), next);
            assert_eq!(encoded_facade_rng.next_u64(), next);
        }
    }
}

/// Small and large sigma select CDT and Ziggurat; empty/singleton batches check RNG semantics.
#[test]
fn gaussian_batches_preserve_scalar_samples_and_rng_consumption() {
    for sigma in [3.2, 30.0] {
        let signed = SignedDiscreteGaussian::<i32>::new(sigma).unwrap();
        // Batch APIs use a scalar loop; larger lengths introduce no additional dispatch.
        for length in [0, 1, 17] {
            check_batch(
                &signed,
                length,
                SignedDiscreteGaussian::sample_vec,
                SignedDiscreteGaussian::sample_to,
            );
        }
        // Table construction is independent of batch length; reuse each encoded sampler.
        for modulus_minus_one in [1_008u64, u64::MAX] {
            let encoded = DiscreteGaussian::new(sigma, modulus_minus_one).unwrap();
            for length in [0, 1, 17] {
                check_batch(
                    &encoded,
                    length,
                    DiscreteGaussian::sample_vec,
                    DiscreteGaussian::sample_to,
                );
            }
        }
    }
}
