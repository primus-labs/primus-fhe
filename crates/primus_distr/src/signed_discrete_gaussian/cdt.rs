use std::marker::PhantomData;

use primus_integer::{AsInto, FheUint, SignedInteger};
use rand::distr::Distribution;

use crate::{
    GaussianError,
    gaussian_core::{
        CDT_MAX_MAGNITUDE, GaussianParameters, build_cdt, encode_modular, encode_signed,
    },
    utils::cdt_index_by,
};

/// Signed CDT sampler using log-space computation.
#[derive(Debug, Clone)]
pub struct SignedCDTSampler<T: SignedInteger> {
    std_dev: f64,
    cdt: Vec<u64>,
    output: PhantomData<T>,
}

impl<T: SignedInteger> SignedCDTSampler<T> {
    /// Generates a signed CDT sampler using log-space arithmetic.
    ///
    /// Returns an error when the parameters are invalid, the support exceeds
    /// the portable CDT limit, or `T` cannot represent every signed sample.
    pub fn new(std_dev: f64, tail_cut: f64) -> Result<Self, GaussianError> {
        let parameters = GaussianParameters::new(std_dev, tail_cut)?;
        Self::from_parameters(parameters)
    }

    pub(crate) fn from_parameters(parameters: GaussianParameters) -> Result<Self, GaussianError> {
        let parameters = parameters
            .validate_cdt_size(CDT_MAX_MAGNITUDE)?
            .validate_signed_output::<T>()?;
        let (std_dev, cdt) = build_cdt(parameters);
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

    #[inline]
    pub(crate) fn maximum_magnitude(&self) -> u64 {
        // The table includes a lower boundary and a terminal sentinel.
        (self.cdt.len() - 2) as u64
    }

    /// Samples sign and magnitude independently of the output encoding.
    #[inline]
    fn sample_magnitude<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> (bool, T) {
        let random = rng.next_u64();
        let index = cdt_index_by(&self.cdt, &random, Ord::cmp);
        (random & 1 == 1, index.as_into())
    }

    /// Uses the same CDT with a modulus already validated against the support.
    #[inline]
    pub(crate) fn sample_encoded<U: FheUint, R: rand::Rng + ?Sized>(
        &self,
        modulus_minus_one: U,
        rng: &mut R,
    ) -> U
    where
        T: SignedInteger<UnsignedInteger = U>,
    {
        let (positive, magnitude) = self.sample_magnitude(rng);
        encode_modular(positive, magnitude.cast_to_unsigned(), modulus_minus_one)
    }
}

impl<T: SignedInteger> Distribution<T> for SignedCDTSampler<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let (positive, magnitude) = self.sample_magnitude(rng);
        encode_signed(positive, magnitude)
    }
}
