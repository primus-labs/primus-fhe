use crate::utils::code::LinearCode;

use algebra::Field;

use std::{cmp::min, iter};

/// ReedSolomonCode
#[derive(Default)]
pub struct ReedSolomonCode {
    message_len: usize,
    codeword_len: usize,
}

impl ReedSolomonCode {
    /// create an instance of ReedSolomonCode
    #[inline]
    pub fn new(message_len: usize, codeword_len: usize) -> Self {
        Self {
            message_len,
            codeword_len,
        }
    }

    /// evaluate the polynomial of coeffs at point x
    #[inline]
    fn evaluate<F: Field>(coeffs: &[F], x: &F) -> F {
        coeffs
            .iter()
            .rev()
            .fold(F::ZERO, |acc, coeff| acc * x + coeff)
    }
}

impl<F: Field> LinearCode<F> for ReedSolomonCode {
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
    fn encode(&self, mut target: impl AsMut<[F]>) {
        let input = target.as_mut()[..min(self.message_len, self.codeword_len)].to_vec();
        let points = iter::successors(Some(F::ONE), move |state| Some(F::ONE + state));
        target
            .as_mut()
            .iter_mut()
            .zip(points)
            .for_each(|(target, x)| *target = Self::evaluate(&input, &x));
    }
}
