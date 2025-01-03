use num_traits::Zero;

use crate::{reduce::ReduceInvAssign, Field, NttField};

use super::FieldNttPolynomial;

impl<F: NttField> FieldNttPolynomial<F> {
    /// Try to calculate the inverse of the polynomial.
    #[inline]
    pub fn try_inv(mut self) -> Result<Self, Self> {
        if self.iter().any(Zero::is_zero) {
            Err(self)
        } else {
            self.iter_mut()
                .for_each(|v| <F as Field>::MODULUS.reduce_inv_assign(v));
            Ok(self)
        }
    }
}
