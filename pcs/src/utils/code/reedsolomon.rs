use crate::utils::code::LinearCode;

use algebra::Field;

use std::{cmp::min, iter, marker::PhantomData};

/// ReedSolomonCode
#[derive(Default, Debug, Clone)]
pub struct ReedSolomonCode<F> {
    message_len: usize,
    codeword_len: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> ReedSolomonCode<F> {
    /// create an instance of ReedSolomonCode
    #[inline]
    pub fn new(message_len: usize, codeword_len: usize) -> Self {
        Self {
            message_len,
            codeword_len,
            ..Default::default()
        }
    }

    /// evaluate the polynomial of coeffs at point x
    #[inline]
    fn evaluate(coeffs: &[F], x: &F) -> F {
        coeffs
            .iter()
            .rev()
            .fold(F::ZERO, |acc, coeff| acc * x + coeff)
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
        let points = iter::successors(Some(F::ONE), move |state| Some(F::ONE + state));
        target
            .as_mut()
            .iter_mut()
            .zip(points)
            .for_each(|(target, x)| *target = Self::evaluate(&input, &x));
    }
}
