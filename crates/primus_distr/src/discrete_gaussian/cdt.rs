use primus_integer::{AsInto, FheUint};
use rand::distr::Distribution;

use crate::{
    GaussianError,
    gaussian_core::{CDT_MAX_MAGNITUDE, GaussianParameters, build_cdt, encode_modular},
    utils::cdt_index_by,
};

/// CDT sampler using log-space computation.
#[derive(Debug, Clone)]
pub struct CDTSampler<T: FheUint> {
    std_dev: f64,
    modulus_minus_one: T,
    cdt: Vec<u64>,
}

impl<T: FheUint> CDTSampler<T> {
    /// Generates a CDT sampler using log-space arithmetic.
    ///
    /// Returns an error when the parameters are invalid, the support exceeds
    /// the portable CDT limit, or the modulus cannot encode every magnitude.
    pub fn new(std_dev: f64, tail_cut: f64, modulus_minus_one: T) -> Result<Self, GaussianError> {
        let parameters = GaussianParameters::new(std_dev, tail_cut)?;
        Self::from_parameters(parameters, modulus_minus_one)
    }

    pub(crate) fn from_parameters(
        parameters: GaussianParameters,
        modulus_minus_one: T,
    ) -> Result<Self, GaussianError> {
        let parameters = parameters
            .validate_cdt_size(CDT_MAX_MAGNITUDE)?
            .validate_modular_output(modulus_minus_one)?;
        let (std_dev, cdt) = build_cdt(parameters);
        Ok(Self {
            std_dev,
            modulus_minus_one,
            cdt,
        })
    }

    /// Returns the standard deviation of this sampler.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.std_dev
    }

    /// Returns the modulus minus one used to encode negative samples.
    #[must_use]
    #[inline]
    pub fn modulus_minus_one(&self) -> T {
        self.modulus_minus_one
    }
}

impl<T: FheUint> Distribution<T> for CDTSampler<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let random: u64 = rng.next_u64();
        let positive = random & 1 == 1;
        let index = cdt_index_by(&self.cdt, &random, Ord::cmp);
        let value: T = index.as_into();

        encode_modular(positive, value, self.modulus_minus_one)
    }
}
