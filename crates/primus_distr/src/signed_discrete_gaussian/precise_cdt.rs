use std::marker::PhantomData;

use primus_integer::{AsInto, SignedInteger};
use rand::{RngExt, distr::Distribution};

use crate::{
    GaussianError,
    gaussian_core::{
        GaussianParameters, PRECISE_CDT_MAX_MAGNITUDE, build_precise_cdt, compare_u256,
    },
    utils::cdt_index_by,
};

/// High-precision signed CDT sampler using a portable 256-bit representation.
#[derive(Debug, Clone)]
pub struct SignedPreciseCDTSampler<T: SignedInteger> {
    std_dev: f64,
    cdt: Vec<[u64; 4]>,
    output: PhantomData<T>,
}

impl<T: SignedInteger> SignedPreciseCDTSampler<T> {
    /// Generates a high-precision signed CDT sampler.
    ///
    /// Returns an error when the parameters are invalid, the support exceeds
    /// the high-precision CDT limit, or `T` cannot represent it.
    pub fn new(std_dev: f64, tail_cut: f64) -> Result<Self, GaussianError> {
        let parameters = GaussianParameters::new(std_dev, tail_cut)?;
        Self::from_parameters(parameters)
    }

    pub(crate) fn from_parameters(parameters: GaussianParameters) -> Result<Self, GaussianError> {
        let parameters = parameters
            .validate_cdt_size(PRECISE_CDT_MAX_MAGNITUDE)?
            .validate_signed_output::<T>()?;
        let (std_dev, cdt) = build_precise_cdt(parameters);
        Ok(Self {
            std_dev,
            cdt,
            output: PhantomData,
        })
    }

    /// Returns the standard deviation of this sampler.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.std_dev
    }
}

impl<T: SignedInteger> Distribution<T> for SignedPreciseCDTSampler<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let mut random = [0; 4];
        rng.fill(&mut random);
        let positive = random[0] & 1 == 1;
        let index = cdt_index_by(&self.cdt, &random, compare_u256);
        let value: T = index.as_into();

        if value.is_zero() {
            return T::ZERO;
        }

        if positive { value } else { T::ZERO - value }
    }
}
