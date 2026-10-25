use primus_integer::{FheInt, FheUint, SignedInteger};
use rand::distr::Distribution;

use crate::{
    GaussianError,
    gaussian_core::{GaussianParameters, ZigguratMagnitudeSampler, encode_modular, encode_signed},
};

/// Discrete Ziggurat sampler with signed output.
#[derive(Clone)]
pub struct SignedDiscreteZiggurat<T: FheInt + SignedInteger> {
    core: ZigguratMagnitudeSampler<T>,
    // Preserve the construction's integer support bound independently of the
    // floating-point sampling tables.
    maximum_magnitude: u64,
}

impl<T: FheInt + SignedInteger> SignedDiscreteZiggurat<T> {
    /// Generates a [`SignedDiscreteZiggurat<T>`].
    ///
    /// Returns an error when the parameters are invalid, `T` cannot represent
    /// the signed support, or Ziggurat setup cannot represent the distribution.
    pub fn new(std_dev: f64, tail_cut: f64) -> Result<Self, GaussianError> {
        let parameters = GaussianParameters::new(std_dev, tail_cut)?;
        Self::from_parameters(parameters)
    }

    pub(crate) fn from_parameters(parameters: GaussianParameters) -> Result<Self, GaussianError> {
        let parameters = parameters.validate_signed_output::<T>()?;
        Ok(Self {
            core: ZigguratMagnitudeSampler::new(parameters)?,
            maximum_magnitude: parameters.maximum_magnitude(),
        })
    }

    /// Returns the standard deviation of this sampler.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.core.standard_deviation()
    }

    #[inline]
    pub(crate) fn maximum_magnitude(&self) -> u64 {
        self.maximum_magnitude
    }

    /// Uses the same magnitude tables with an already validated modulus.
    #[inline]
    pub(crate) fn sample_encoded<U: FheUint, R: rand::Rng + ?Sized>(
        &self,
        modulus_minus_one: U,
        rng: &mut R,
    ) -> U
    where
        T: SignedInteger<UnsignedInteger = U>,
    {
        let (positive, magnitude) = self.core.sample(rng);
        encode_modular(positive, magnitude.cast_to_unsigned(), modulus_minus_one)
    }
}

impl<T: FheInt + SignedInteger> Distribution<T> for SignedDiscreteZiggurat<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let (positive, magnitude) = self.core.sample(rng);
        encode_signed(positive, magnitude)
    }
}
