use primus_integer::FheUint;
use rand::distr::Distribution;

use crate::{
    GaussianError,
    gaussian_core::{GaussianParameters, ZigguratMagnitudeSampler, encode_modular},
};

/// Discrete Ziggurat sampler with modular unsigned output.
#[derive(Clone)]
pub struct DiscreteZiggurat<T: FheUint> {
    core: ZigguratMagnitudeSampler<T>,
    modulus_minus_one: T,
}

impl<T: FheUint> DiscreteZiggurat<T> {
    /// Generates a [`DiscreteZiggurat<T>`].
    ///
    /// Returns an error when the parameters are invalid, the modulus cannot
    /// encode the support, or Ziggurat setup cannot represent the distribution.
    pub fn new(std_dev: f64, tail_cut: f64, modulus_minus_one: T) -> Result<Self, GaussianError> {
        let parameters = GaussianParameters::new(std_dev, tail_cut)?;
        Self::from_parameters(parameters, modulus_minus_one)
    }

    pub(crate) fn from_parameters(
        parameters: GaussianParameters,
        modulus_minus_one: T,
    ) -> Result<Self, GaussianError> {
        let parameters = parameters.validate_modular_output(modulus_minus_one)?;
        Ok(Self {
            core: ZigguratMagnitudeSampler::new(parameters)?,
            modulus_minus_one,
        })
    }

    /// Returns the standard deviation of this sampler.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.core.standard_deviation()
    }

    /// Returns the modulus minus one used to encode negative samples.
    #[must_use]
    #[inline]
    pub fn modulus_minus_one(&self) -> T {
        self.modulus_minus_one
    }
}

impl<T: FheUint> Distribution<T> for DiscreteZiggurat<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let (positive, magnitude) = self.core.sample(rng);
        encode_modular(positive, magnitude, self.modulus_minus_one)
    }
}
