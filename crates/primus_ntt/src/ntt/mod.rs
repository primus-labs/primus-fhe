use primus_data::{DataMut, RawData};
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

use crate::{NttError, root::PrimitiveRoot};

#[cfg(feature = "concrete-ntt")]
mod concrete;
mod primitive;
mod u32;
mod u64;

#[cfg(feature = "concrete-ntt")]
pub use concrete::prime32::Concrete32Table;
#[cfg(feature = "concrete-ntt")]
pub use concrete::prime64::Concrete64Table;
pub use primitive::UintNttTable;
pub use u32::U32NttTable;
pub use u64::U64NttTable;

/// An abstract for Number Theory Transform.
pub trait NttTable: Sized + Send + Sync {
    /// The value type.
    type ValueT: PrimitiveRoot;

    /// Creates a new [`NttTable`].
    fn new<M>(log_n: u32, modulus: M) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>;

    /// Get the polynomial length.
    fn poly_length(&self) -> usize;

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a polynomial to a ntt polynomial.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
        &self,
        poly: Polynomial<S>,
    ) -> NttPolynomial<S>;

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a ntt polynomial to a polynomial.
    ///
    /// # Arguments
    ///
    /// * `values` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
        &self,
        values: NttPolynomial<S>,
    ) -> Polynomial<S>;

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
    /// This function transforms a polynomial slice with coefficient in `[0, modulus)`
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
    /// This function transforms a ntt polynomial slice with coefficient in `[0, modulus)`
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
