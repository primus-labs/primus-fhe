use crate::{
    decompose::{NonPowOf2ApproxSignedBasis, SignedOnceDecompose},
    Field,
};

use super::FieldPolynomial;

impl<F: Field> FieldPolynomial<F> {
    /// Decomposes [`FieldPolynomial<F>`] according to [SignedOnceDecompose].
    #[inline]
    pub fn approx_signed_decompose(
        &self,
        once_decompose: SignedOnceDecompose<<F as Field>::ValueT>,
        carries: &mut [bool],
        decompose_poly: &mut [<F as Field>::ValueT],
    ) {
        once_decompose.decompose_slice_inplace(self.as_slice(), carries, decompose_poly);
    }

    /// Init carries and adjusted polynomial for a [`FieldPolynomial<F>`].
    #[inline]
    pub fn init_adjust_poly_carries(
        &self,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        carries: &mut [bool],
        adjust_poly: &mut Self,
    ) {
        basis.init_value_carry_slice(self.as_ref(), carries, adjust_poly.as_mut());
    }

    /// Init carries and adjusted polynomial for a [`FieldPolynomial<F>`].
    #[inline]
    pub fn init_adjust_poly_carries_assign(
        &mut self,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        carries: &mut [bool],
    ) {
        basis.init_value_carry_slice_inplace(self.as_mut(), carries);
    }
}
