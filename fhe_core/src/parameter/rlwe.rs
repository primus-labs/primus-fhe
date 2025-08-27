use algebra::{decompose::NonPowOf2ApproxSignedBasis, random::DiscreteGaussian, Field, NttField};

use crate::RingSecretKeyType;

/// Rlwe Parameters.
#[derive(Debug)]
pub struct RlweParameters<Q: NttField> {
    /// The dimension, refers to **N** in the paper.
    pub dimension: usize,
    /// **RLWE** message modulus, refers to **t** in the paper.
    pub plain_modulus_value: <Q as Field>::ValueT,
    /// The modulus, refers to **Q** in the paper.
    pub modulus: <Q as Field>::ValueT,
    /// The distribution type of the secret key.
    pub secret_key_type: RingSecretKeyType,
    /// The noise error's standard deviation.
    pub noise_standard_deviation: f64,
}

impl<Q: NttField> Copy for RlweParameters<Q> {}

impl<Q: NttField> Clone for RlweParameters<Q> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<Q: NttField> RlweParameters<Q> {
    /// Returns the dimension.
    #[inline]
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns the noise distribution.
    #[inline]
    pub fn noise_distribution(&self) -> DiscreteGaussian<<Q as Field>::ValueT> {
        DiscreteGaussian::new(0.0, self.noise_standard_deviation, Q::MINUS_ONE).unwrap()
    }

    /// Returns the noise distribution.
    #[inline]
    pub fn noise_distribution_div_count(
        &self,
        count: u32,
    ) -> DiscreteGaussian<<Q as Field>::ValueT> {
        let var = self.noise_standard_deviation * self.noise_standard_deviation;
        let sigma = (var / count as f64).sqrt();
        DiscreteGaussian::new(0.0, sigma, Q::MINUS_ONE).unwrap()
    }

    /// Returns the cipher modulus of this [`RlweParameters<Q>`].
    #[inline]
    pub fn cipher_modulus(&self) -> <Q as Field>::Modulus {
        <Q as Field>::MODULUS
    }
}

/// Rgsw Parameters.
#[derive(Debug)]
pub struct GadgetRlweParameters<Q: NttField> {
    /// The dimension, refers to **N** in the paper.
    pub dimension: usize,
    /// The modulus, refers to **Q** in the paper.
    pub modulus: <Q as Field>::ValueT,
    /// The distribution type of the secret key.
    pub secret_key_type: RingSecretKeyType,
    /// The noise error's standard deviation.
    pub noise_standard_deviation: f64,
    /// Decompose basis for `Q`.
    pub basis: NonPowOf2ApproxSignedBasis<<Q as Field>::ValueT>,
}

impl<Q: NttField> GadgetRlweParameters<Q> {
    /// Returns the decompose basis.
    #[inline]
    pub fn basis(&self) -> &NonPowOf2ApproxSignedBasis<<Q as Field>::ValueT> {
        &self.basis
    }

    /// Returns the dimension.
    #[inline]
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns the noise distribution.
    #[inline]
    pub fn noise_distribution(&self) -> DiscreteGaussian<<Q as Field>::ValueT> {
        DiscreteGaussian::new(0.0, self.noise_standard_deviation, Q::MINUS_ONE).unwrap()
    }

    /// Returns the noise distribution.
    #[inline]
    pub fn noise_distribution_div_count(
        &self,
        count: u32,
    ) -> DiscreteGaussian<<Q as Field>::ValueT> {
        let var = self.noise_standard_deviation * self.noise_standard_deviation;
        let sigma = (var / count as f64).sqrt();
        DiscreteGaussian::new(0.0, sigma, Q::MINUS_ONE).unwrap()
    }
}

impl<Q: NttField> Copy for GadgetRlweParameters<Q> {}

impl<Q: NttField> Clone for GadgetRlweParameters<Q> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}
