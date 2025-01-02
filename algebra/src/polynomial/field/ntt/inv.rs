use num_traits::Inv;

use crate::{reduce::ReduceInvAssign, Field, NttField};

use super::FieldNttPolynomial;

impl<F: NttField> Inv for FieldNttPolynomial<F> {
    type Output = Self;

    #[inline]
    fn inv(mut self) -> Self::Output {
        self.iter_mut()
            .for_each(|v| <F as Field>::MODULUS.reduce_inv_assign(v));
        self
    }
}
