use primus_distr::{DiscreteGaussian, SecretKeyDistr, SecretKeySampler};
use primus_integer::FheUint;
use rand::{Rng, SeedableRng, rngs::StdRng};

/// Fixed seeds compare signed/modular samples; sparse, balanced, and dense weights select different samplers.
#[test]
fn representations_preserve_distribution_and_logical_weights() {
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::binary(0.3),
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::UniformTernary,
        SecretKeyDistr::ternary(0.2, 0.4),
        SecretKeyDistr::fixed_hamming_weight_binary(67, 7),
        SecretKeyDistr::fixed_hamming_weight_binary(67, 33),
        SecretKeyDistr::fixed_hamming_weight_binary(67, 60),
        SecretKeyDistr::fixed_hamming_weight_ternary(67, 13),
        SecretKeyDistr::fixed_hamming_weight_ternary(67, 67),
        SecretKeyDistr::fixed_composition_ternary(67, 5, 8),
        SecretKeyDistr::fixed_composition_ternary(67, 22, 22),
        SecretKeyDistr::fixed_composition_ternary(67, 60, 4),
        SecretKeyDistr::fixed_composition_ternary(67, 4, 60),
        SecretKeyDistr::gaussian(3.2),
        SecretKeyDistr::gaussian(30.0),
    ] {
        let sampler = SecretKeySampler::<u32>::new(distr);
        let expected_bound = match distr {
            SecretKeyDistr::Gaussian {
                standard_deviation: 3.2,
            } => 38,
            SecretKeyDistr::Gaussian { .. } => 360,
            _ => 1,
        };
        assert_eq!(sampler.maximum_magnitude(), expected_bound);
        // The signed sample and its logical weights are independent of the encoding modulus.
        let mut signed_rng = StdRng::seed_from_u64(201);
        let input = sampler.sample_signed(67, &mut signed_rng);
        let expected_next = signed_rng.next_u64();
        match distr {
            SecretKeyDistr::FixedHammingWeightBinary { hamming_weight } => {
                assert_eq!(input.iter().filter(|&&v| v == 1).count(), hamming_weight);
                assert!(input.iter().all(|&v| v == 0 || v == 1));
            }
            SecretKeyDistr::FixedCompositionTernary {
                negative_one_weight,
                one_weight,
            } => {
                assert_eq!(
                    input.iter().filter(|&&v| v == -1).count(),
                    negative_one_weight
                );
                assert_eq!(input.iter().filter(|&&v| v == 1).count(), one_weight);
                assert!(input.iter().all(|&v| (-1..=1).contains(&v)));
            }
            SecretKeyDistr::FixedHammingWeightTernary { hamming_weight } => {
                assert_eq!(input.iter().filter(|&&v| v != 0).count(), hamming_weight);
                assert!(input.iter().all(|&v| (-1..=1).contains(&v)));
            }
            _ => {}
        }
        for modulus in [1_009i64, 1i64 << 32] {
            let mut encoded_rng = StdRng::seed_from_u64(201);
            let mut output = [u32::MAX; 67];
            sampler.sample_encoded_to(&mut output, (modulus - 1) as u32, &mut encoded_rng);
            let expected: Vec<u32> = input
                .iter()
                .map(|&v| i64::from(v).rem_euclid(modulus) as u32)
                .collect();
            assert_eq!(output.as_slice(), expected, "{distr:?}");
            assert_eq!(encoded_rng.next_u64(), expected_next);
        }
    }
}

/// The smallest encodable support and the native modulus are valid for both word widths.
#[test]
fn encoded_modulus_validation_preserves_the_support_boundary() {
    fn check<T: FheUint>() {
        for (distr, expected_bound) in [
            (SecretKeyDistr::UniformBinary, 1u128),
            (SecretKeyDistr::SparseTernary, 1),
            (SecretKeyDistr::gaussian(1.0), 12),
        ] {
            let sampler = SecretKeySampler::<T>::new(distr);
            let bound = sampler.maximum_magnitude();
            let actual_bound: u128 = bound.as_into();
            assert_eq!(actual_bound, expected_bound);
            assert_eq!(sampler.validate_modulus(bound), Ok(()));
            assert_eq!(sampler.validate_modulus(T::MAX), Ok(()));
            assert_eq!(
                sampler.validate_modulus(bound - T::ONE),
                Err(primus_distr::SecretKeySamplerError::ModulusTooSmall {
                    maximum_magnitude: expected_bound,
                    modulus_minus_one: expected_bound - 1,
                })
            );
        }
    }
    check::<u32>();
    check::<u64>();
}

/// Validate length and overflowing compositions before consuming RNG or touching output.
#[test]
fn invalid_weight_is_rejected_before_sampling_or_writing() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    for distr in [
        SecretKeyDistr::fixed_hamming_weight_binary(7, 7),
        SecretKeyDistr::fixed_hamming_weight_ternary(7, 7),
        SecretKeyDistr::fixed_composition_ternary(7, 3, 4),
        SecretKeyDistr::FixedCompositionTernary {
            negative_one_weight: usize::MAX,
            one_weight: 1,
        },
    ] {
        let sampler = SecretKeySampler::<u32>::new(distr);
        let mut output = [19; 6];
        assert_eq!(
            sampler.validate_length(output.len()),
            Err(primus_distr::SecretKeySamplerError::InvalidWeight { length: 6 })
        );
        let mut rng = StdRng::seed_from_u64(202);
        let mut expected = StdRng::seed_from_u64(202);
        assert!(
            catch_unwind(AssertUnwindSafe(
                || sampler.sample_signed_to(&mut output, &mut rng)
            ))
            .is_err()
        );
        assert_eq!(output, [19; 6]);
        assert_eq!(rng.next_u64(), expected.next_u64());
    }
}

/// Raw enum construction bypasses checked distribution constructors, so the sampler validates again.
#[test]
fn sampler_rejects_invalid_probabilities_in_raw_variants() {
    for distr in [
        SecretKeyDistr::Binary {
            one_probability: f64::NAN,
        },
        SecretKeyDistr::Ternary {
            negative_one_probability: -0.5,
            one_probability: 0.5,
        },
        SecretKeyDistr::Ternary {
            negative_one_probability: 0.6,
            one_probability: 0.5,
        },
        SecretKeyDistr::Ternary {
            negative_one_probability: 0.0,
            one_probability: f64::INFINITY,
        },
    ] {
        assert!(matches!(
            SecretKeySampler::<u32>::try_new(distr),
            Err(primus_distr::SecretKeySamplerError::InvalidProbabilities)
        ));
        assert!(std::panic::catch_unwind(|| SecretKeySampler::<u32>::new(distr)).is_err());
    }
    assert!(matches!(
        SecretKeySampler::<u32>::try_new(SecretKeyDistr::gaussian(f64::NAN)),
        Err(primus_distr::SecretKeySamplerError::Gaussian(_))
    ));
}

/// Secret-key adapters preserve backend samples and RNG consumption for support-bound/native moduli.
#[test]
fn shared_gaussian_tables_match_modular_backends() {
    fn check<T: FheUint>() {
        for sigma in [3.2, 30.0] {
            let sampler = SecretKeySampler::<T>::new(SecretKeyDistr::gaussian(sigma));
            for modulus_minus_one in [sampler.maximum_magnitude(), T::MAX] {
                let oracle = DiscreteGaussian::new(sigma, modulus_minus_one).unwrap();
                // Gaussian batches use the same scalar loop at every length.
                for length in [0, 1, 67] {
                    let mut expected_rng = StdRng::seed_from_u64(203);
                    let mut allocated_rng = StdRng::seed_from_u64(203);
                    let mut output_rng = StdRng::seed_from_u64(203);
                    let expected = oracle.sample_vec(length, &mut expected_rng);
                    let allocated =
                        sampler.sample_encoded(length, modulus_minus_one, &mut allocated_rng);
                    let mut output = vec![T::MAX; length];
                    sampler.sample_encoded_to(&mut output, modulus_minus_one, &mut output_rng);
                    assert_eq!(allocated, expected);
                    assert_eq!(output, expected);
                    let next = expected_rng.next_u64();
                    assert_eq!(allocated_rng.next_u64(), next);
                    assert_eq!(output_rng.next_u64(), next);
                }
            }
        }
    }
    check::<u16>();
    check::<u32>();
    check::<u64>();
}
