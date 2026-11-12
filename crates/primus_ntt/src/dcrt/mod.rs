use primus_reduce::FieldContext;
use primus_shape::PolyLength;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{MonomialNttTable, NttError, NttTable, U32NttTable, U64NttTable, UintNttTable};

/// A collection of NTT tables sharing the same polynomial length.
///
/// Each contained table operates on one CRT modulus. The nonzero number of
/// moduli is fixed after construction because the table slice is not exposed
/// mutably. [`Self::poly_length`] is the checked ring length `N`, whereas
/// [`Self::rns_poly_len`] is the total `moduli_count * N` element count.
///
/// Full transforms assume one complete RNS polynomial in modulus-major order,
/// matching [`Self::ntt_tables`], and check the length in debug builds.
/// [`Self::transform_prefix_slice`] and [`Self::inverse_transform_prefix_slice`]
/// check that the length describes a nonempty prefix of complete limbs and
/// transform them in the same modulus order.
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

        // Prepare the opted-in registry with the table. Worker startup remains
        // asynchronous; callers measuring kernel-only allocations must first
        // synchronize their configured pool, rather than count its startup.
        #[cfg(feature = "parallel")]
        if poly_length.get() >= 4096 && ntt_tables.len() >= 2 {
            let _ = rayon::current_num_threads();
        }

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

    /// Transforms one nonempty ordered prefix of this table's CRT limbs.
    ///
    /// With the `parallel` feature, N>=4096 and at least two limbs, this uses
    /// at most four contiguous tasks in the current Rayon pool. Configure the
    /// default pool with `RAYON_NUM_THREADS`, or build a pool with
    /// `ThreadPoolBuilder::num_threads` and select it with `ThreadPool::install`.
    /// Smaller inputs and single-worker pools stay serial. Existing limbs are
    /// borrowed in place; no ciphertext scratch or random sampling is introduced.
    /// Without the `parallel` feature no thread pool is initialized.
    ///
    /// # Panics
    /// Rejects an empty, partial-limb or overlong prefix before writes.
    ///
    /// # Correctness
    /// Each limb inherits [`NttTable::transform_slice`]'s canonical input and
    /// representation contract, using the first `poly.len()/N` ordered tables.
    #[inline]
    pub fn transform_prefix_slice(&self, poly: &mut [Ntt::ValueT]) {
        self.transform_prefix_kernel::<false>(poly);
    }

    /// Inversely transforms a nonempty ordered CRT prefix in place.
    ///
    /// Scheduling and complete-prefix checks match [`Self::transform_prefix_slice`].
    /// # Panics
    /// Rejects an empty, partial-limb or overlong prefix before writes.
    /// # Correctness
    /// Each limb inherits [`NttTable::inverse_transform_slice`]'s input range,
    /// originating table, root order and normalization contract.
    #[inline]
    pub fn inverse_transform_prefix_slice(&self, poly: &mut [Ntt::ValueT]) {
        self.transform_prefix_kernel::<true>(poly);
    }

    fn transform_prefix_kernel<const INVERSE: bool>(&self, poly: &mut [Ntt::ValueT]) {
        let n = self.poly_length.get();
        assert!(
            !poly.is_empty() && poly.len() & (n - 1) == 0 && poly.len() <= self.rns_poly_len,
            "DCRT transform requires a nonempty complete limb prefix"
        );
        let tables = &self.ntt_tables[..(poly.len() >> self.poly_length.log_n())];
        #[cfg(feature = "parallel")]
        if n >= 4096 && tables.len() >= 2 {
            let workers = rayon::current_num_threads().min(4).min(tables.len());
            if workers > 1 {
                let limbs_per_task = tables.len().div_ceil(workers);
                tables
                    .par_chunks(limbs_per_task)
                    .zip(poly.par_chunks_mut(limbs_per_task * n))
                    .for_each(|(tables, values)| {
                        Self::transform_limbs::<INVERSE>(tables, values, n)
                    });
                return;
            }
        }
        Self::transform_limbs::<INVERSE>(tables, poly, n);
    }

    fn transform_limbs<const INVERSE: bool>(tables: &[Ntt], values: &mut [Ntt::ValueT], n: usize) {
        for (table, limb) in tables.iter().zip(values.chunks_exact_mut(n)) {
            if INVERSE {
                table.inverse_transform_slice(limb);
            } else {
                table.transform_slice(limb);
            }
        }
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
