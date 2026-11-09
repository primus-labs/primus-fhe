use primus_reduce::FieldContext;
use primus_shape::PolyLength;

use crate::{MonomialNttTable, NttError, NttTable, U32NttTable, U64NttTable, UintNttTable};

/// A collection of NTT tables sharing the same polynomial length.
///
/// Each contained table operates on one CRT modulus. The nonzero number of
/// moduli is fixed after construction because the table slice is not exposed
/// mutably. [`Self::poly_length`] is the checked ring length `N`, whereas
/// [`Self::rns_poly_len`] is the total `moduli_count * N` element count.
///
/// Transform inputs and outputs contain exactly one complete RNS polynomial in
/// modulus-major order, matching the order of [`Self::ntt_tables`]. The caller
/// maintains the complete layout; length checks are debug diagnostics only.
/// Coefficient ranges, root choice, NTT order and normalization follow the
/// component [`NttTable`] contract.
#[derive(Clone)]
pub struct DcrtTable<Ntt> {
    ntt_tables: Vec<Ntt>,
    poly_length: PolyLength,
    rns_poly_len: usize,
}

/// DCRT table using the generic unsigned-integer NTT implementation.
pub type UintDcrtTable<T> = DcrtTable<UintNttTable<T>>;

/// DCRT table using the optimized 32-bit NTT implementation.
pub type U32DcrtTable = DcrtTable<U32NttTable>;

/// DCRT table using the optimized 64-bit NTT implementation.
pub type U64DcrtTable = DcrtTable<U64NttTable>;

impl<Ntt> DcrtTable<Ntt>
where
    Ntt: NttTable,
{
    /// Creates one NTT table for every CRT modulus.
    ///
    /// # Errors
    /// Returns [`NttError::EmptyModuli`] if the modulus list is empty.
    /// Returns [`NttError::CrtPolynomialLengthOverflow`] if the combined
    /// coefficient count overflows, before constructing any component table.
    /// Otherwise propagates the component table's construction errors.
    pub fn new<M>(poly_length: PolyLength, moduli: &[M]) -> Result<Self, NttError<Ntt::ValueT>>
    where
        M: FieldContext<Ntt::ValueT>,
    {
        if moduli.is_empty() {
            return Err(NttError::EmptyModuli);
        }
        let rns_poly_len = poly_length
            .get()
            .checked_mul(moduli.len())
            .ok_or(NttError::CrtPolynomialLengthOverflow)?;
        let ntt_tables = moduli
            .iter()
            .map(|&modulus| Ntt::new(poly_length, modulus))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            ntt_tables,
            poly_length,
            rns_poly_len,
        })
    }

    /// Returns the NTT table for every CRT modulus.
    #[inline]
    pub fn ntt_tables(&self) -> &[Ntt] {
        &self.ntt_tables
    }

    /// Returns an iterator over the NTT tables.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, Ntt> {
        self.ntt_tables.iter()
    }

    /// Returns the polynomial length shared by all NTT tables.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.poly_length
    }

    /// Returns the number of CRT moduli.
    #[must_use]
    #[inline]
    pub fn moduli_count(&self) -> usize {
        self.ntt_tables.len()
    }

    /// Returns the total stored element count `moduli_count * N` for one RNS polynomial.
    ///
    /// This count applies to both coefficient and NTT representations.
    #[must_use]
    #[inline]
    pub fn rns_poly_len(&self) -> usize {
        self.rns_poly_len
    }

    /// Transforms every CRT limb in place.
    ///
    /// # Correctness
    /// Storage must have exactly [`Self::rns_poly_len`] elements in the table's
    /// modulus-major order. Inherits [`NttTable::transform_slice`]'s input range and
    /// representation requirements; complete storage is assumed in release.
    #[inline]
    pub fn transform_slice(&self, poly: &mut [Ntt::ValueT]) {
        let poly_length = self.poly_length().get();
        debug_assert_eq!(self.rns_poly_len(), poly.len());
        self.iter()
            .zip(poly.chunks_exact_mut(poly_length))
            .for_each(|(table, poly)| table.transform_slice(poly));
    }

    /// Inversely transforms every DCRT limb in place.
    ///
    /// # Correctness
    /// Storage must have exactly [`Self::rns_poly_len`] elements in the table's
    /// modulus-major order. Inherits [`NttTable::inverse_transform_slice`]'s input range and
    /// representation requirements; complete storage is assumed in release.
    #[inline]
    pub fn inverse_transform_slice(&self, poly: &mut [Ntt::ValueT]) {
        let poly_length = self.poly_length().get();
        debug_assert_eq!(self.rns_poly_len(), poly.len());
        self.iter()
            .zip(poly.chunks_exact_mut(poly_length))
            .for_each(|(table, values)| table.inverse_transform_slice(values));
    }
}

impl<Ntt: MonomialNttTable> DcrtTable<Ntt> {
    /// Transforms `X^degree` for every CRT modulus.
    ///
    /// # Correctness
    /// `values` must contain exactly [`Self::rns_poly_len`] elements in the
    /// table's modulus-major order; complete storage is assumed in release.
    pub fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [Ntt::ValueT]) {
        let poly_length = self.poly_length().get();
        debug_assert_eq!(self.rns_poly_len(), values.len());
        self.iter()
            .zip(values.chunks_exact_mut(poly_length))
            .for_each(|(table, values)| table.transform_coeff_one_monomial(degree, values));
    }
}
