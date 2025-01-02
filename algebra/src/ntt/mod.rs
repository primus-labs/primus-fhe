use crate::AlgebraError;

mod table;

pub use table::*;

pub trait NttTable: Sized + Clone + Send + Sync {
    type ValueT;
    type Modulus;

    /// Creates a new [`NttTable`].
    fn new(modulus: <Self as NttTable>::Modulus, log_n: u32) -> Result<Self, AlgebraError>;

    /// Get the polynomial modulus degree.
    fn dimension(&self) -> usize;
}

pub trait NumberTheoryTransform: NttTable {
    type CoeffPoly: Clone;
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
}
