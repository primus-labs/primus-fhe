use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_factor::FactorSliceOps;
use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_poly::{
    ArrayBase, CrtPolynomial, CrtPolynomialIter, CrtPolynomialIterMut, DcrtPolynomial,
};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::{context::DcrtGlevContext, ggsw::DcrtGgsw};

use super::DcrtGlwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`primus_poly::CrtPolynomial`] with same poly length and moduli count, `k` is the dimension.
#[derive(Clone)]
pub struct CrtGlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(CrtGlwe<S>);
impl_bytes_conversion!(CrtGlwe<S>);
impl_zero!(CrtGlwe<S>);
impl_iters!(CrtGlwe);
impl_iter_sub_structure!(CrtGlwe<S>, CrtPolynomial, crt_poly);
impl_basic_operation_multiple_modulus!(CrtGlwe<S>);
impl_crt_ntt!(CrtGlwe<S>, DcrtGlwe);

impl<S, T> CrtGlwe<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Extracts mutable slice of `a` and `b` of this [`CrtGlwe<S>`].
    #[inline]
    pub fn a_b_mut_slices(&mut self, mid: usize) -> (&mut [T], &mut [T]) {
        self.0.split_at_mut(mid)
    }

    /// Extracts mutable `a` and `b` of this [`CrtGlwe<S>`].
    #[inline]
    pub fn a_b_mut(
        &mut self,
        mid: usize,
    ) -> (CrtPolynomialIterMut<'_, T>, CrtPolynomial<&mut [T]>) {
        let (a, b) = self.0.split_at_mut(mid);
        (CrtPolynomialIterMut::new(a, b.len()), CrtPolynomial(b))
    }

    pub fn mul_scalar_assign<M>(
        &mut self,
        scalar_residue: &[T],
        poly_length: usize,
        crt_poly_len: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
    {
        self.iter_crt_poly_mut(crt_poly_len)
            .for_each(|mut crt_poly| {
                crt_poly.mul_scalar_assign(scalar_residue, poly_length, moduli);
            });
    }

    /// Perform `self = self * X^r`.
    pub fn mul_monic_monomial_assign<M>(
        &mut self,
        r: usize,
        poly_length: usize,
        crt_poly_len: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
    {
        if r < poly_length {
            let rotate = |poly: &mut [T], modulus: M| {
                poly.rotate_right(r);
                modulus.reduce_neg_slice_assign(&mut poly[0..r]);
            };

            self.iter_crt_poly_mut(crt_poly_len)
                .for_each(|mut crt_poly| {
                    crt_poly
                        .iter_each_modulus_mut(poly_length)
                        .zip(moduli)
                        .for_each(|(poly, &modulus)| rotate(poly, modulus));
                });
        } else {
            debug_assert!(r < poly_length * 2);
            let r = r - poly_length;
            let rotate = |poly: &mut [T], modulus: M| {
                poly.rotate_right(r);
                modulus.reduce_neg_slice_assign(&mut poly[r..]);
            };

            self.iter_crt_poly_mut(crt_poly_len)
                .for_each(|mut crt_poly| {
                    crt_poly
                        .iter_each_modulus_mut(poly_length)
                        .zip(moduli)
                        .for_each(|(poly, &modulus)| rotate(poly, modulus));
                });
        }
    }
}

impl<S, T> CrtGlwe<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Extracts slice of `a` and `b` of this [`CrtGlwe<S>`].
    #[inline]
    pub fn a_b_slices(&self, mid: usize) -> (&[T], &[T]) {
        self.0.split_at(mid)
    }

    /// Extracts slice of `a` and `b` of this [`CrtGlwe<S>`].
    #[inline]
    pub fn a_b(&self, mid: usize) -> (CrtPolynomialIter<'_, T>, CrtPolynomial<&[T]>) {
        let (a, b) = self.0.split_at(mid);
        (CrtPolynomialIter::new(a, b.len()), CrtPolynomial(b))
    }

    pub fn mul_scalar_to<M, A>(
        &self,
        scalar_residue: &[T],
        result: &mut CrtGlwe<A>,
        poly_length: usize,
        crt_poly_len: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + DataMut,
    {
        self.iter_crt_poly(crt_poly_len)
            .zip(result.iter_crt_poly_mut(crt_poly_len))
            .for_each(|(in_crt_poly, mut out_crt_poly)| {
                in_crt_poly.mul_scalar_to(scalar_residue, &mut out_crt_poly, poly_length, moduli);
            });
    }

    pub fn mul_factor_to<F, A>(
        &self,
        scalar: &[F],
        result: &mut CrtGlwe<A>,
        poly_length: usize,
        crt_poly_len: usize,
        moduli: &[T],
    ) where
        F: Copy + FactorSliceOps<T>,
        A: RawData<Elem = T> + DataMut,
    {
        self.iter_crt_poly(crt_poly_len)
            .zip(result.iter_crt_poly_mut(crt_poly_len))
            .for_each(|(in_crt_poly, mut out_crt_poly)| {
                in_crt_poly.mul_factor_to(scalar, &mut out_crt_poly, poly_length, moduli);
            });
    }

    /// Performs a multiplication on the `self` [`CrtGlwe<S>`] with another `dcrt_poly` [`DcrtPolynomial<A>`],
    /// store the result into `result` [`DcrtGlwe<T>`].
    #[inline]
    pub fn mul_dcrt_polynomial_to<M, Table, A, B>(
        &self,
        dcrt_poly: &DcrtPolynomial<A>,
        result: &mut DcrtGlwe<B>,
        moduli: &[M],
        table: &Table,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = table.poly_length();
        let dcrt_poly_len = table.crt_poly_length();

        result.0.copy_from_slice(self.as_ref());

        result.iter_dcrt_poly_mut(dcrt_poly_len).for_each(|mut x| {
            table.transform_slice(x.0);
            x.mul_assign(dcrt_poly, poly_length, moduli);
        });
    }

    pub fn mul_dcrt_ggsw_to<M, Table, A, B>(
        &self,
        dcrt_ggsw: &DcrtGgsw<A>,
        result: &mut DcrtGlwe<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &Table,
        rns_base: &RNSBase<T, M>,
        context: &mut DcrtGlevContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let crt_poly_len = table.crt_poly_length();
        let dcrt_glev_len = basis.decompose_length() * self.as_ref().len();

        result.set_zero();

        dcrt_ggsw
            .iter_dcrt_glev(dcrt_glev_len)
            .zip(self.iter_crt_poly(crt_poly_len))
            .for_each(|(dcrt_glev, crt_poly)| {
                result.add_dcrt_glev_mul_crt_poly_assign(
                    &dcrt_glev, &crt_poly, basis, table, rns_base, context,
                );
            });
    }
}
