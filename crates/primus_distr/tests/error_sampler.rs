use std::{
    convert::Infallible,
    panic::{AssertUnwindSafe, catch_unwind},
};

use primus_distr::{
    CenteredBinomial, CenteredBinomialError, ErrorDistribution, ErrorSampler, ErrorSamplerError,
};
use primus_integer::{AsInto, ConstBounded, FheUint};
use rand::{Rng, SeedableRng, TryCryptoRng, TryRng, distr::Distribution, rngs::StdRng};

struct WordRng {
    word: u64,
    draws: usize,
}

impl TryRng for WordRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        panic!("CBD must consume u64 words");
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.draws += 1;
        Ok(self.word)
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Infallible> {
        for chunk in output.chunks_mut(8) {
            chunk.copy_from_slice(&self.try_next_u64()?.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}
impl TryCryptoRng for WordRng {}

fn choose(n: usize, k: usize) -> usize {
    (0..k).fold(1, |value, i| value * (n - i) / (i + 1))
}

/// Enumerating every bit string gives the exact law, without statistical tests.
#[test]
fn centered_binomial_matches_exact_probabilities_and_variance() {
    for eta in 1..=4 {
        let sampler = CenteredBinomial::<i32>::new(eta).unwrap();
        let mut counts = vec![0; (2 * eta + 1) as usize];
        for word in 0..1_u64 << (2 * eta) {
            let mut rng = WordRng { word, draws: 0 };
            let sample = sampler.sample(&mut rng);
            counts[(sample + eta as i32) as usize] += 1;
            assert_eq!(rng.draws, 1);
        }
        let mut second_moment = 0;
        let mut first_moment = 0_i64;
        for (index, &count) in counts.iter().enumerate() {
            assert_eq!(count, choose(2 * eta as usize, index));
            let sample = index as i64 - i64::from(eta);
            first_moment += sample * count as i64;
            second_moment += sample * sample * count as i64;
        }
        assert_eq!(first_moment, 0);
        assert_eq!(2 * second_moment, i64::from(eta) * (1 << (2 * eta)));
    }
}

/// CBD21/32 exercise both signs, exact support endpoints and the 64-bit boundary.
#[test]
fn centered_binomial_support_and_unused_bits_are_exact() {
    for eta in [1, 21, 32] {
        let sampler = CenteredBinomial::<i64>::new(eta).unwrap();
        let mask = (1_u64 << eta) - 1;
        for (word, expected) in [
            (0, 0),
            (mask, i64::from(eta)),
            (mask << eta, -i64::from(eta)),
            (u64::MAX, 0),
        ] {
            let mut rng = WordRng { word, draws: 0 };
            assert_eq!(sampler.sample(&mut rng), expected);
            assert_eq!(rng.draws, 1);
        }
        if eta < 32 {
            let mut rng = WordRng {
                word: u64::MAX << (2 * eta),
                draws: 0,
            };
            assert_eq!(sampler.sample(&mut rng), 0);
        }
    }
    for eta in [0, 33, u32::MAX] {
        assert!(matches!(CenteredBinomial::<i32>::new(eta),
            Err(CenteredBinomialError::InvalidEta { eta: invalid }) if invalid == eta));
    }
}

#[test]
fn signed_and_crt_batches_share_samples_and_rng_consumption() {
    fn check<T: FheUint>() {
        let moduli = [769_u64, 1153].map(T::as_from);
        let replay_rng = || StdRng::seed_from_u64(504);
        for distribution in [
            ErrorDistribution::Gaussian {
                standard_deviation: 3.2,
            },
            ErrorDistribution::Gaussian {
                standard_deviation: 30.0,
            },
            ErrorDistribution::CenteredBinomial { eta: 1 },
            ErrorDistribution::CenteredBinomial { eta: 21 },
            ErrorDistribution::CenteredBinomial { eta: 32 },
        ] {
            let sampler = ErrorSampler::<T>::try_new(distribution).unwrap();
            assert_eq!(sampler.distribution(), distribution);
            for length in [0, 1, 17] {
                let mut scalar_rng = replay_rng();
                let signed: Vec<T::SignedInteger> = (0..length)
                    .map(|_| sampler.sample(&mut scalar_rng))
                    .collect();
                let next = scalar_rng.next_u64();
                let mut batch = vec![T::SignedInteger::MAX; length];
                let mut batch_rng = replay_rng();
                sampler.sample_signed_to(&mut batch, &mut batch_rng);
                assert_eq!(batch, signed);
                assert_eq!(batch_rng.next_u64(), next);

                let mut encoded = vec![T::MAX; length * moduli.len()];
                let mut crt_rng = replay_rng();
                sampler.sample_crt_to(&mut encoded, length, &moduli, &mut crt_rng);
                assert_eq!(crt_rng.next_u64(), next);
                for (index, modulus) in moduli.iter().enumerate() {
                    let modulus: i128 = (*modulus).as_into();
                    for (actual, sample) in encoded[index * length..(index + 1) * length]
                        .iter()
                        .zip(&signed)
                    {
                        let actual: i128 = (*actual).as_into();
                        let sample: i128 = (*sample).as_into();
                        assert_eq!(actual, sample.rem_euclid(modulus));
                    }
                }
            }
        }
    }
    check::<u32>();
    check::<u64>();
}

/// Invalid public layouts/support fail before modifying output or consuming RNG.
#[test]
fn error_sampler_validates_configuration_and_batch_boundaries() {
    assert!(matches!(
        ErrorSampler::<u32>::try_new(ErrorDistribution::Gaussian {
            standard_deviation: f64::NAN,
        }),
        Err(ErrorSamplerError::Gaussian(_))
    ));
    assert!(matches!(
        ErrorSampler::<u64>::try_new(ErrorDistribution::CenteredBinomial { eta: 0 }),
        Err(ErrorSamplerError::CenteredBinomial(
            CenteredBinomialError::InvalidEta { eta: 0 }
        ))
    ));
    let sampler =
        ErrorSampler::<u32>::try_new(ErrorDistribution::CenteredBinomial { eta: 21 }).unwrap();
    assert!(sampler.validate_modulus(21).is_ok());
    assert!(matches!(
        sampler.validate_modulus(20),
        Err(ErrorSamplerError::ModulusTooSmall {
            maximum_magnitude: 21,
            modulus_minus_one: 20,
        })
    ));
    for (length, moduli) in [
        (1, &[97][..]),
        (2, &[97, 17]),
        (2, &[97, 0]),
        (usize::MAX, &[97, 193]),
    ] {
        let mut output = [87_u32; 4];
        let mut rng = WordRng {
            word: u64::MAX,
            draws: 0,
        };
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                sampler.sample_crt_to(&mut output, length, moduli, &mut rng);
            }))
            .is_err()
        );
        assert_eq!(output, [87; 4]);
        assert_eq!(rng.draws, 0);
    }
}
