//! Defines Number Theory Transform algorithms.

use crate::{arith::PrimitiveRoot, AlgebraError};

mod table;

pub use table::*;

/// An abstract for ntt table generation.
pub trait NttTable: Sized + Send + Sync {
    /// The value type.
    type ValueT;

    /// The modulus type.
    type ModulusT: PrimitiveRoot<Self::ValueT>;

    /// Creates a new [`NttTable`].
    fn new(modulus: Self::ModulusT, log_n: u32) -> Result<Self, AlgebraError>;

    /// Get the polynomial modulus degree.
    fn dimension(&self) -> usize;
}

/// An abstract for Number Theory Transform.
pub trait NumberTheoryTransform: NttTable {
    /// Polynomial type with coefficients.
    type CoeffPoly: Clone;
    /// Ntt Polynomial type.
    type NttPoly: Clone;

    /// Perform a fast number theory transform.
    ///
    /// This function transforms a polynomial to a ntt polynomial.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    #[inline]
    fn transform(&self, poly: &Self::CoeffPoly) -> Self::NttPoly {
        self.transform_inplace(poly.clone())
    }

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a polynomial to a ntt polynomial.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn transform_inplace(&self, poly: Self::CoeffPoly) -> Self::NttPoly;

    /// Perform a fast inverse number theory transform.
    ///
    /// This function transforms a ntt polynomial to a polynomial.
    ///
    /// # Arguments
    ///
    /// * `values` - inputs in bit-reversed order, outputs in normal order
    #[inline]
    fn inverse_transform(&self, values: &Self::NttPoly) -> Self::CoeffPoly {
        self.inverse_transform_inplace(values.clone())
    }

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a ntt polynomial to a polynomial.
    ///
    /// # Arguments
    ///
    /// * `values` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform_inplace(&self, values: Self::NttPoly) -> Self::CoeffPoly;

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a polynomial slice with coefficient in `[0, 4*modulus)`
    /// to a ntt polynomial slice with coefficient in `[0, 4*modulus)`.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn lazy_transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]);

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a polynomial slice with coefficient in `[0, 4*modulus)`
    /// to a ntt polynomial slice with coefficient in `[0, modulus)`.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]);

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a ntt polynomial slice with coefficient in `[0, 2*modulus)`
    /// to a polynomial slice with coefficient in `[0, 2*modulus)`.
    ///
    /// # Arguments
    ///
    /// * `values` - inputs in bit-reversed order, outputs in normal order
    fn lazy_inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]);

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a ntt polynomial slice with coefficient in `[0, 2*modulus)`
    /// to a polynomial slice with coefficient in `[0, modulus)`.
    ///
    /// # Arguments
    ///
    /// * `values` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]);

    /// Perform a fast number theory transform for **monomial** `coeff*X^degree` in place.
    fn transform_monomial(
        &self,
        coeff: Self::ValueT,
        degree: usize,
        values: &mut [<Self as NttTable>::ValueT],
    );

    /// Perform a fast number theory transform for **monomial** `X^degree` in place.
    fn transform_coeff_one_monomial(
        &self,
        degree: usize,
        values: &mut [<Self as NttTable>::ValueT],
    );

    /// Perform a fast number theory transform for **monomial** `-X^degree` in place.
    fn transform_coeff_minus_one_monomial(
        &self,
        degree: usize,
        values: &mut [<Self as NttTable>::ValueT],
    );

    /// Perform a fast lazy polynomial multiplication assignment.
    ///
    /// The coefficients of the result polynomial are in the range `[0, 2*modulus)`
    /// and fall back to the range `[0, modulus)` if the ntt table does not support
    /// this special case.
    fn lazy_mul_assign(&self, a: &mut Self::CoeffPoly, b: &Self::CoeffPoly);

    /// Perform a fast polynomial multiplication assignment.
    ///
    /// The coefficients of the result polynomial are in the range `[0, modulus)`.
    fn mul_assign(&self, a: &mut Self::CoeffPoly, b: &Self::CoeffPoly);

    /// Perform a fast lazy polynomial multiplication in place.
    ///
    /// The coefficients of the result polynomial are in the range `[0, 2*modulus)`
    /// and fall back to the range `[0, modulus)` if the ntt table does not support
    /// this special case.
    fn lazy_mul_inplace(&self, a: &Self::CoeffPoly, b: &Self::CoeffPoly, c: &mut Self::CoeffPoly);

    /// Perform a fast polynomial multiplication in place.
    ///
    /// The coefficients of the result polynomial are in the range `[0, modulus)`.
    fn mul_inplace(&self, a: &Self::CoeffPoly, b: &Self::CoeffPoly, c: &mut Self::CoeffPoly);
}
