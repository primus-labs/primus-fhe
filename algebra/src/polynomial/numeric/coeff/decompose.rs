use crate::{
    decompose::{NonPowOf2ApproxSignedBasis, SignedOnceDecompose},
    integer::UnsignedInteger,
};

use super::Polynomial;

impl<T: UnsignedInteger> Polynomial<T> {
    /// Decomposes [`Polynomial<T>`] according to [SignedOnceDecompose].
    #[inline]
    pub fn approx_signed_decompose(
        &self,
        once_decompose: SignedOnceDecompose<T>,
        carries: &mut [bool],
        decompose_poly: &mut [T],
    ) {
        once_decompose.decompose_slice_inplace(self.as_slice(), carries, decompose_poly);
    }

    /// Init carries and adjusted polynomial for a [`Polynomial<T>`].
    #[inline]
    pub fn init_adjust_poly_carries(
        &self,
        basis: &NonPowOf2ApproxSignedBasis<T>,
        carries: &mut [bool],
        adjust_poly: &mut Self,
    ) {
        basis.init_value_carry_slice(self.as_ref(), carries, adjust_poly.as_mut());
    }

    /// Init carries and adjusted polynomial for a [`Polynomial<T>`].
    #[inline]
    pub fn init_adjust_poly_carries_assign(
        &mut self,
        basis: &NonPowOf2ApproxSignedBasis<T>,
        carries: &mut [bool],
    ) {
        basis.init_value_carry_slice_inplace(self.as_mut(), carries);
    }
}
