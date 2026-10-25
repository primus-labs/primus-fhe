use primus_integer::{AsInto, FheUint};
use rand::{RngExt, distr::Distribution};

use crate::{
    GaussianError,
    gaussian_core::{
        GaussianParameters, PRECISE_CDT_MAX_MAGNITUDE, build_precise_cdt, compare_u256,
        encode_modular,
    },
    utils::cdt_index_by,
};

/// High-precision CDT sampler using a portable 256-bit representation.
#[derive(Debug, Clone)]
pub struct PreciseCDTSampler<T: FheUint> {
    std_dev: f64,
    modulus_minus_one: T,
    cdt: Vec<[u64; 4]>,
}

impl<T: FheUint> PreciseCDTSampler<T> {
    /// Generates a high-precision CDT sampler.
    ///
    /// Returns an error when the parameters are invalid, the support exceeds
    /// the high-precision CDT limit, or the modulus cannot encode it.
    pub fn new(std_dev: f64, tail_cut: f64, modulus_minus_one: T) -> Result<Self, GaussianError> {
        let parameters = GaussianParameters::new(std_dev, tail_cut)?;
        Self::from_parameters(parameters, modulus_minus_one)
    }

    pub(crate) fn from_parameters(
        parameters: GaussianParameters,
        modulus_minus_one: T,
    ) -> Result<Self, GaussianError> {
        let parameters = parameters
            .validate_cdt_size(PRECISE_CDT_MAX_MAGNITUDE)?
            .validate_modular_output(modulus_minus_one)?;
        let (std_dev, cdt) = build_precise_cdt(parameters);
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
}

impl<T: FheUint> Distribution<T> for PreciseCDTSampler<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let mut random = [0; 4];
        rng.fill(&mut random);
        let positive = random[0] & 1 == 1;
        let index = cdt_index_by(&self.cdt, &random, compare_u256);
        let value: T = index.as_into();

        encode_modular(positive, value, self.modulus_minus_one)
    }
}
