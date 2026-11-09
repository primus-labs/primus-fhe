use primus_integer::{FheInt, Integer};
use rand::{Rng, distr::Distribution};

/// The ternary sampler.
///
/// prob\[1] = prob\[-1] = 0.25
///
/// prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct SparseTernaryDistr<T: Integer> {
    minus_one: T,
}

impl<T: Integer> SparseTernaryDistr<T> {
    /// Creates a new [`SparseTernaryDistr`].
    #[inline]
    pub fn new(minus_one: T) -> Self {
        Self { minus_one }
    }
}

impl<T: Integer> Distribution<T> for SparseTernaryDistr<T> {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> T {
        [T::ZERO, T::ZERO, T::ONE, self.minus_one][(rng.next_u32() & 0b11) as usize]
    }
}

/// Integer cumulative thresholds for a three-outcome distribution.
/// Each input probability is rounded down to a multiple of `2^-64`. Their
/// integer sum is capped at `2^64` to handle floating-point boundary rounding.
/// Endpoints are separate variants, so inner loops use only u64 thresholds.
#[derive(Clone, Copy)]
pub(crate) enum TernarySampler {
    Constant(i8),
    Nonzero { negative_end: u64 },
    General { negative_end: u64, nonzero_end: u64 },
}

impl TernarySampler {
    pub(crate) fn new(negative: f64, positive: f64) -> Self {
        Self::try_new(negative, positive).unwrap_or_else(|error| panic!("{error}"))
    }

    /// Classify endpoints outside the sampling loop; u128 can hold the exclusive bound 2^64.
    pub(crate) fn try_new(
        negative: f64,
        positive: f64,
    ) -> Result<Self, crate::SecretKeySamplerError> {
        crate::secret_key_distr::check_ternary_probabilities(negative, positive)?;
        const FULL: u128 = 1u128 << 64;
        let negative_end = (negative * FULL as f64) as u128;
        let positive_weight = (positive * FULL as f64) as u128;
        let nonzero_end = (negative_end + positive_weight).min(FULL);
        Ok(if negative_end == FULL {
            Self::Constant(-1)
        } else if nonzero_end == 0 {
            Self::Constant(0)
        } else if positive_weight == FULL {
            Self::Constant(1)
        } else if nonzero_end == FULL {
            Self::Nonzero {
                negative_end: negative_end as u64,
            }
        } else {
            Self::General {
                negative_end: negative_end as u64,
                nonzero_end: nonzero_end as u64,
            }
        })
    }

    /// Encode -1 with the supplied representative; constant distributions consume no RNG.
    pub(crate) fn sample_to<T: FheInt, R: Rng + rand::CryptoRng>(
        &self,
        output: &mut [T],
        minus_one: T,
        rng: &mut R,
    ) {
        match *self {
            Self::Constant(value) => {
                output.fill([minus_one, T::ZERO, T::ONE][(value + 1) as usize])
            }
            Self::Nonzero { negative_end } => {
                let values = [minus_one, T::ONE];
                for out in output {
                    *out = values[(rng.next_u64() >= negative_end) as usize];
                }
            }
            Self::General {
                negative_end,
                nonzero_end,
            } => {
                let values = [minus_one, T::ONE, T::ZERO];
                for out in output {
                    let random = rng.next_u64();
                    let index =
                        usize::from(random >= negative_end) + usize::from(random >= nonzero_end);
                    *out = values[index];
                }
            }
        }
    }
}
