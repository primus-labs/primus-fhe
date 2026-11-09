use std::marker::PhantomData;

use primus_integer::SignedInteger;
use rand::distr::Distribution;

/// Invalid centered-binomial parameter or signed output representation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CenteredBinomialError {
    /// One random word supplies the two independent eta-bit strings.
    #[error("centered-binomial eta must be in 1..=32, got {eta}")]
    InvalidEta {
        /// Requested binomial parameter.
        eta: u32,
    },
    /// Every sample in the inclusive support must fit the signed output.
    #[error("centered-binomial eta {eta} exceeds output maximum {output_maximum}")]
    OutputTypeTooNarrow {
        /// Inclusive sample magnitude.
        eta: u32,
        /// Largest positive signed output value.
        output_maximum: u128,
    },
}

/// Exact difference of two independent Binomial(eta, 1/2) variables.
///
/// The support is `[-eta, eta]` and the variance is `eta/2`. Each sample
/// consumes one random u64, using its low eta bits and the following eta bits;
/// unused high bits are discarded. This is not a Gaussian approximation.
#[derive(Debug, Clone, Copy)]
pub struct CenteredBinomial<T: SignedInteger> {
    eta: u32,
    mask: u64,
    output: PhantomData<T>,
}

impl<T: SignedInteger> CenteredBinomial<T> {
    /// Prepares an exact sampler for eta in 1..=32.
    ///
    /// # Errors
    /// Rejects an eta outside that interval or a signed type whose positive
    /// range cannot represent the complete inclusive support.
    pub fn new(eta: u32) -> Result<Self, CenteredBinomialError> {
        if !(1..=32).contains(&eta) {
            return Err(CenteredBinomialError::InvalidEta { eta });
        }
        let output_maximum: u128 = T::MAX.as_into();
        if u128::from(eta) > output_maximum {
            return Err(CenteredBinomialError::OutputTypeTooNarrow {
                eta,
                output_maximum,
            });
        }
        Ok(Self {
            eta,
            mask: (1_u64 << eta) - 1,
            output: PhantomData,
        })
    }

    /// Returns the configured binomial parameter and inclusive magnitude bound.
    #[must_use]
    pub fn eta(&self) -> u32 {
        self.eta
    }

    /// Overwrites signed output without allocation or per-coefficient dispatch.
    /// Empty output consumes no randomness; a panicking RNG may leave partial output.
    pub fn sample_to<R: rand::Rng + rand::CryptoRng + ?Sized>(
        &self,
        output: &mut [T],
        rng: &mut R,
    ) {
        for value in output {
            *value = self.sample(rng);
        }
    }
}

impl<T: SignedInteger> Distribution<T> for CenteredBinomial<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let word = rng.next_u64();
        let positive = (word & self.mask).count_ones() as i32;
        let negative = ((word >> self.eta) & self.mask).count_ones() as i32;
        T::as_from(positive - negative)
    }
}
