use primus_data::{DataMut, RawData};
use primus_poly::{CrtPolynomial, DcrtPolynomial};

use crate::{DcrtTable, NttTable, U64NttTable};

/// Wrapping crt NTT for 64bit primes.
#[derive(Clone)]
pub struct U64DcrtTable {
    ntt_tables: Vec<U64NttTable>,
    poly_length: usize,
    moduli_count: usize,
    crt_poly_length: usize,
}

impl DcrtTable for U64DcrtTable {
    type ValueT = u64;

    type NttTables = U64NttTable;

    #[inline]
    fn new<M>(log_n: u32, moduli: &[M]) -> Result<Self, crate::NttError<Self::ValueT>>
    where
        M: primus_reduce::FieldContext<Self::ValueT>,
    {
        let moduli_count = moduli.len();
        let poly_length = 1 << log_n;
        let crt_poly_length = moduli_count * poly_length;

        let mut ntt_tables = Vec::with_capacity(moduli_count);
        for modulus in moduli {
            ntt_tables.push(Self::NttTables::new(log_n, *modulus)?);
        }
        Ok(Self {
            ntt_tables,
            poly_length,
            moduli_count,
            crt_poly_length,
        })
    }

    #[inline]
    fn ntt_tables(&self) -> &[Self::NttTables] {
        &self.ntt_tables
    }

    #[inline]
    fn iter(&self) -> std::slice::Iter<'_, Self::NttTables> {
        self.ntt_tables.iter()
    }

    #[inline]
    fn poly_length(&self) -> usize {
        self.poly_length
    }

    #[inline]
    fn moduli_count(&self) -> usize {
        self.moduli_count
    }

    #[inline]
    fn crt_poly_length(&self) -> usize {
        self.crt_poly_length
    }

    #[inline]
    fn transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
        &self,
        mut crt_poly: CrtPolynomial<S>,
    ) -> DcrtPolynomial<S> {
        let poly_length = self.poly_length();

        self.iter()
            .zip(crt_poly.iter_each_modulus_mut(poly_length))
            .for_each(|(t, p)| t.transform_slice(p));

        DcrtPolynomial::new(crt_poly.0)
    }

    #[inline]
    fn inverse_transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
        &self,
        mut dcrt_poly: DcrtPolynomial<S>,
    ) -> CrtPolynomial<S> {
        let poly_length = self.poly_length();

        self.iter()
            .zip(dcrt_poly.iter_each_modulus_mut(poly_length))
            .for_each(|(t, p)| t.inverse_transform_slice(p));

        CrtPolynomial::new(dcrt_poly.0)
    }

    #[inline]
    fn lazy_transform_slice(&self, poly: &mut [Self::ValueT]) {
        let poly_length = self.poly_length();
        self.iter()
            .zip(poly.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, poly)| ntt_table.lazy_transform_slice(poly))
    }

    #[inline]
    fn transform_slice(&self, poly: &mut [Self::ValueT]) {
        let poly_length = self.poly_length();
        self.iter()
            .zip(poly.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, poly)| ntt_table.transform_slice(poly))
    }

    #[inline]
    fn lazy_inverse_transform_slice(&self, poly: &mut [Self::ValueT]) {
        let poly_length = self.poly_length();
        self.iter()
            .zip(poly.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, values)| ntt_table.lazy_inverse_transform_slice(values))
    }

    #[inline]
    fn inverse_transform_slice(&self, poly: &mut [Self::ValueT]) {
        let poly_length = self.poly_length();
        self.iter()
            .zip(poly.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, values)| ntt_table.inverse_transform_slice(values))
    }
}
