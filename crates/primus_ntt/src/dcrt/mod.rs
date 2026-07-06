use primus_data::{DataMut, RawData};
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;

use crate::{NttError, NttTable, PrimitiveRoot};

#[cfg(feature = "concrete-ntt")]
mod concrete;
mod primitive;

#[cfg(feature = "concrete-ntt")]
pub use concrete::prime32::CrtConcrete32Table;
#[cfg(feature = "concrete-ntt")]
pub use concrete::prime64::CrtConcrete64Table;
pub use primitive::UintCrtNttTable;

/// Double-CRT (DCRT) table: a collection of NTT tables sharing the same
/// polynomial length but operating over distinct prime moduli.
///
/// Used to compose/decompose polynomials in RNS form for HE operations.
pub trait DcrtTable: Sized + Send + Sync {
    /// The value type.
    type ValueT: PrimitiveRoot;

    /// The concrete NTT table type for each CRT limb.
    type NttTables: NttTable<ValueT = Self::ValueT>;

    /// Creates a new [`DcrtTable`].
    fn new<M>(log_n: u32, moduli: &[M]) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>;

    /// Returns a reference to the ntt tables.
    fn ntt_tables(&self) -> &[Self::NttTables];

    /// Returns an iterator over the ntt tables.
    fn iter(&self) -> std::slice::Iter<'_, Self::NttTables>;

    /// Returns the polynomial length `N` (same for every CRT limb).
    fn poly_length(&self) -> usize;

    /// Returns the number of CRT limbs (distinct prime moduli).
    fn moduli_count(&self) -> usize;

    /// Returns the total CRT polynomial length (`N × moduli_count`).
    fn crt_poly_length(&self) -> usize;

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a crt polynomial to a dcrt polynomial.
    ///
    /// # Arguments
    ///
    /// * `crt_poly` - inputs in normal order, outputs in bit-reversed order
    fn transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
        &self,
        crt_poly: CrtPolynomial<S>,
    ) -> DcrtPolynomial<S>;

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a dcrt polynomial to a crt polynomial.
    ///
    /// # Arguments
    ///
    /// * `dcrt_poly` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
        &self,
        dcrt_poly: DcrtPolynomial<S>,
    ) -> CrtPolynomial<S>;

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a crt polynomial slice with coefficient in `[0, 4*modulus)`
    /// to a dcrt polynomial slice with coefficient in `[0, 4*modulus)`.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn lazy_transform_slice(&self, poly: &mut [Self::ValueT]);

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a polynomial slice with coefficient in `[0, modulus)`
    /// to a ntt polynomial slice with coefficient in `[0, modulus)`.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn transform_slice(&self, poly: &mut [Self::ValueT]);

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a ntt polynomial slice with coefficient in `[0, 2*modulus)`
    /// to a polynomial slice with coefficient in `[0, 2*modulus)`.
    ///
    /// # Arguments
    ///
    /// * `values` - inputs in bit-reversed order, outputs in normal order
    fn lazy_inverse_transform_slice(&self, poly: &mut [Self::ValueT]);

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a ntt polynomial slice with coefficient in `[0, modulus)`
    /// to a polynomial slice with coefficient in `[0, modulus)`.
    ///
    /// # Arguments
    ///
    /// * `values` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform_slice(&self, poly: &mut [Self::ValueT]);

    /// NTT of monomial `coeff * X^degree` across all moduli.
    fn transform_monomial(&self, coeff: Self::ValueT, degree: usize, values: &mut [Self::ValueT]) {
        let poly_length = self.poly_length();
        self.iter()
            .zip(values.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, values)| ntt_table.transform_monomial(coeff, degree, values))
    }

    /// NTT of monomial `X^degree` across all moduli.
    fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [Self::ValueT]) {
        let poly_length = self.poly_length();
        self.iter()
            .zip(values.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, values)| ntt_table.transform_coeff_one_monomial(degree, values))
    }

    /// NTT of monomial `-X^degree` across all moduli.
    fn transform_coeff_minus_one_monomial(&self, degree: usize, values: &mut [Self::ValueT]) {
        let poly_length = self.poly_length();
        self.iter()
            .zip(values.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, values)| {
                ntt_table.transform_coeff_minus_one_monomial(degree, values)
            })
    }
}
