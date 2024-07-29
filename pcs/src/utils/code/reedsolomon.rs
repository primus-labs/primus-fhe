use crate::utils::code::LinearCode;

use algebra::{AbstractExtensionField, Field};
use serde::{Deserialize, Serialize};

use std::{cmp::min, iter, marker::PhantomData};

/// Define the struct of Reed-Solomon Code
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ReedSolomonCode<F> {
    // The length of messages.
    message_len: usize,
    // The length of codeword.
    codeword_len: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> ReedSolomonCode<F> {
    /// Create an instance of ReedSolomonCode
    ///
    /// # Arguments.
    ///
    /// * `message_len` - The length of messages.
    /// * `codeword_len` - The length of codeword.
    #[inline]
    pub fn new(message_len: usize, codeword_len: usize) -> Self {
        Self {
            message_len,
            codeword_len,
            _marker: PhantomData,
        }
    }

    /// Evaluate the polynomial of coefficients at point x.
    ///
    /// # Arguments.
    ///
    /// * `coeffs` - The coefficients.
    /// * `x` - The point.
    #[inline]
    fn evaluate(coeffs: &[F], x: F) -> F {
        coeffs
            .iter()
            .rev()
            .fold(F::zero(), |acc, coeff| acc * x + coeff)
    }
    /// Evaluate the polynomial at point x with coefficients in the extension field
    ///
    /// # Arguments.
    ///
    /// * `coeffs` - The coefficients.
    /// * `x` - The point.
    #[inline]
    fn evaluate_ext<EF: AbstractExtensionField<F>>(coeffs: &[EF], x: F) -> EF {
        coeffs
            .iter()
            .rev()
            .fold(EF::zero(), |acc, coeff| acc * x + coeff)
    }
}

impl<F: Field> LinearCode<F> for ReedSolomonCode<F> {
    #[inline]
    fn message_len(&self) -> usize {
        self.message_len
    }

    #[inline]
    fn codeword_len(&self) -> usize {
        self.codeword_len
    }

    #[inline]
    fn distance(&self) -> f64 {
        (self.codeword_len - self.message_len + 1) as f64 / self.codeword_len as f64
    }

    #[inline]
    fn proximity_gap(&self) -> f64 {
        1.0 / 2.0
    }

    #[inline]
    fn encode(&self, target: &mut [F]) {
        let input = target[..min(self.message_len, self.codeword_len)].to_vec();
        let points = iter::successors(Some(F::one()), move |state| Some(F::one() + state));
        target
            .as_mut()
            .iter_mut()
            .zip(points)
            .for_each(|(target, x)| *target = Self::evaluate(&input, x));
    }

    fn encode_ext<EF>(&self, target: &mut [EF])
    where
        F: Field,
        EF: algebra::AbstractExtensionField<F>,
    {
        let input = target[..min(self.message_len, self.codeword_len)].to_vec();
        let points = iter::successors(Some(F::one()), move |state| Some(F::one() + state));
        target
            .as_mut()
            .iter_mut()
            .zip(points)
            .for_each(|(target, x)| *target = Self::evaluate_ext(&input, x));
    }
}
