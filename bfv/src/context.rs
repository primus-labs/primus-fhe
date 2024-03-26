//! Context of BFV

use algebra::FieldDiscreteGaussianSampler;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::cell::RefCell;

use crate::DIMENSION_N;

/// Define the context of BFV scheme.
#[derive(Debug, Clone)]
pub struct BFVContext {
    rlwe_dimension: usize,
    csrng: RefCell<ChaCha12Rng>,
    sampler: FieldDiscreteGaussianSampler,
}

impl BFVContext {
    /// Create a new instance.
    #[inline]
    pub fn new() -> Self {
        let csrng = ChaCha12Rng::from_entropy();
        Self {
            rlwe_dimension: DIMENSION_N,
            csrng: RefCell::new(csrng),
            sampler: FieldDiscreteGaussianSampler::new(0.0, 3.2).unwrap(),
        }
    }
    /// Returns the rlwe_dimension.
    #[inline]
    pub fn rlwe_dimension(&self) -> usize {
        self.rlwe_dimension
    }

    /// Returns the sampler.
    #[inline]
    pub fn sampler(&self) -> FieldDiscreteGaussianSampler {
        self.sampler
    }

    /// Returns the csrng of [`BFVContext`].
    #[inline]
    pub fn csrng_mut(&self) -> std::cell::RefMut<'_, ChaCha12Rng> {
        self.csrng.borrow_mut()
    }
}

impl Default for BFVContext {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
