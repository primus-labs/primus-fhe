use algebra::{decompose::NonPowOf2ApproxSignedBasis, Field, NttField};

use crate::RingSecretKeyType;

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

impl<Q: NttField> Copy for GadgetRlweParameters<Q> {}

impl<Q: NttField> Clone for GadgetRlweParameters<Q> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}
