use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_factor::{FactorSliceOps, ShoupFactor};
use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_poly::{
    ArrayBase, BigUintPolynomial, CrtPolynomial, DcrtPolynomial, DcrtPolynomialIter,
    DcrtPolynomialIterMut,
};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::{
    context::{DcrtGlevContext, DcrtGlevContextRefMut},
    glev::DcrtGlev,
};

use super::CrtGlwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`DcrtPolynomial`] with same poly length and moduli count, `k` is the dimension.
#[derive(Clone)]
pub struct DcrtGlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(DcrtGlwe<S>);
impl_bytes_conversion!(DcrtGlwe<S>);
impl_zero!(DcrtGlwe<S>);
impl_iters!(DcrtGlwe);
impl_iter_sub_structure!(DcrtGlwe<S>, DcrtPolynomial, dcrt_poly);
impl_basic_operation_multiple_modulus!(DcrtGlwe<S>);
impl_crt_intt!(DcrtGlwe<S>, CrtGlwe);

impl<S, T> DcrtGlwe<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Extracts mutable slice of `a` and `b` of this [`DcrtGlwe<S>`].
    #[inline]
    pub fn a_b_mut_slices(&mut self, mid: usize) -> (&mut [T], &mut [T]) {
        self.as_mut().split_at_mut(mid)
    }

    /// Extracts mutable `a` and `b` of this [`DcrtGlwe<S>`].
    #[inline]
    pub fn a_b_mut(
        &mut self,
        mid: usize,
    ) -> (DcrtPolynomialIterMut<'_, T>, DcrtPolynomial<&mut [T]>) {
        let (a, b) = self.as_mut().split_at_mut(mid);
        (DcrtPolynomialIterMut::new(a, b.len()), DcrtPolynomial(b))
    }

    /// Negates each DCRT polynomial component in place.
    pub fn neg_assign<M>(&mut self, dcrt_poly_len: usize, poly_length: usize, moduli: &[M])
    where
        M: FieldContext<T>,
    {
        self.iter_dcrt_poly_mut(dcrt_poly_len)
            .for_each(|mut dcrt_poly| {
                dcrt_poly.neg_assign(poly_length, moduli);
            });
    }

    /// Multiplies each DCRT polynomial component by `scalar_residue` in place.
    pub fn mul_scalar_assign<M>(
        &mut self,
        scalar_residue: &[T],
        poly_length: usize,
        dcrt_poly_len: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
    {
        self.iter_dcrt_poly_mut(dcrt_poly_len)
            .for_each(|mut dcrt_poly| {
                dcrt_poly.mul_scalar_assign(scalar_residue, poly_length, moduli);
            });
    }

    /// Performs `self *= scalar` according to `moduli`.
    #[inline]
    pub fn mul_factor_assign<F>(
        &mut self,
        scalar: &[F],
        poly_length: usize,
        dcrt_poly_len: usize,
        moduli: &[T],
    ) where
        F: Copy + FactorSliceOps<T>,
    {
        self.iter_dcrt_poly_mut(dcrt_poly_len)
            .for_each(|mut dcrt_poly| {
                dcrt_poly.mul_factor_assign(scalar, poly_length, moduli);
            });
    }

    /// Performs `self += dcrt_glwe * dcrt_poly` in place.
    pub fn add_dcrt_glwe_mul_dcrt_polynomial_assign<M, A, B>(
        &mut self,
        dcrt_glwe: &DcrtGlwe<A>,
        dcrt_poly: &DcrtPolynomial<B>,
        poly_length: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
    {
        let dcrt_poly_len = dcrt_poly.dcrt_poly_length();

        self.iter_dcrt_poly_mut(dcrt_poly_len)
            .zip(dcrt_glwe.iter_dcrt_poly(dcrt_poly_len))
            .for_each(|(mut x, y)| {
                x.add_mul_assign(&y, dcrt_poly, poly_length, moduli);
            });
    }

    /// Inverse butterfly with monomial multiply.
    /// `(self, result) = (self + rhs, (self_orig - rhs) * dcrt_poly)`
    pub fn butterfly_mul_dcrt_polynomial_to<M, A, B, C>(
        &mut self,
        rhs: &DcrtGlwe<A>,
        dcrt_poly: &DcrtPolynomial<B>,
        result: &mut DcrtGlwe<C>,
        poly_length: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let dcrt_poly_len = dcrt_poly.dcrt_poly_length();
        self.iter_dcrt_poly_mut(dcrt_poly_len)
            .zip(rhs.iter_dcrt_poly(dcrt_poly_len))
            .zip(result.iter_dcrt_poly_mut(dcrt_poly_len))
            .for_each(|((mut a, s), mut b)| {
                a.butterfly_mul_to(&s, dcrt_poly, &mut b, poly_length, moduli);
            });
    }

    /// Inverse butterfly with a Shoup-factor DCRT polynomial.
    /// `(self, result) = (self + rhs, (self_orig - rhs) * factor_poly)`.
    ///
    /// `self` and `rhs` are expected in `[0, q)`. Both outputs are written
    /// back in `[0, q)`.
    pub fn butterfly_mul_factor_to<A, C>(
        &mut self,
        rhs: &DcrtGlwe<A>,
        factor_poly: &[ShoupFactor<T>],
        result: &mut DcrtGlwe<C>,
        poly_length: usize,
        moduli: &[T],
    ) where
        A: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let dcrt_poly_len = factor_poly.len();
        self.iter_dcrt_poly_mut(dcrt_poly_len)
            .zip(rhs.iter_dcrt_poly(dcrt_poly_len))
            .zip(result.iter_dcrt_poly_mut(dcrt_poly_len))
            .for_each(|((mut a, s), mut b)| {
                a.butterfly_mul_factor_to(&s, factor_poly, &mut b, poly_length, moduli);
            });
    }

    /// Performs `self += dcrt_glev * crt_poly` using the given decomposition basis and NTT table.
    pub fn add_dcrt_glev_mul_crt_poly_assign<M, Table, A, B>(
        &mut self,
        dcrt_glev: &DcrtGlev<A>,
        crt_poly: &CrtPolynomial<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &Table,
        rns_base: &RNSBase<T, M>,
        context: &mut DcrtGlevContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
    {
        let poly_length = table.poly_length();
        let big_uint_value_len = rns_base.big_uint_value_len();
        let basis_value = basis.basis_value();

        let moduli = rns_base.moduli();
        let dcrt_glwe_len = self.0.len();

        let DcrtGlevContextRefMut {
            adjust_big_uint_values,
            decomposed_unsigned_values,
            carries,
            multi_residues,
            compose_buffer,
        } = context.as_mut();

        debug_assert_eq!(
            adjust_big_uint_values.len(),
            poly_length * big_uint_value_len
        );
        debug_assert_eq!(decomposed_unsigned_values.len(), poly_length);
        debug_assert_eq!(carries.len(), poly_length);
        debug_assert_eq!(multi_residues.len(), poly_length * moduli.len());
        debug_assert_eq!(
            dcrt_glev.as_ref().len(),
            dcrt_glwe_len * basis.decompose_length()
        );

        rns_base.compose_multiple_values_to(
            crt_poly.as_ref(),
            adjust_big_uint_values,
            poly_length,
            compose_buffer,
        );

        basis.init_value_carry_slice_inplace(adjust_big_uint_values, carries, big_uint_value_len);

        dcrt_glev
            .iter_dcrt_glwe(dcrt_glwe_len)
            .zip(basis.decomposer_iter())
            .for_each(|(dcrt_glwe, once_decomposer)| {
                once_decomposer.unsigned_decompose_slice_to(
                    adjust_big_uint_values.as_ref(),
                    decomposed_unsigned_values,
                    carries,
                    big_uint_value_len,
                );

                rns_base.wrapping_decompose_small_values_to(
                    decomposed_unsigned_values.as_ref(),
                    multi_residues,
                    poly_length,
                    basis_value,
                );

                table.transform_slice(multi_residues);

                self.add_dcrt_glwe_mul_dcrt_polynomial_assign(
                    &dcrt_glwe,
                    &DcrtPolynomial(&*multi_residues),
                    poly_length,
                    moduli,
                );
            });
    }

    /// Performs `self += dcrt_glev * big_uint_poly` using the given decomposition basis and NTT table.
    pub fn add_dcrt_glev_mul_big_uint_poly_assign<M, Table, A, B>(
        &mut self,
        dcrt_glev: &DcrtGlev<A>,
        big_uint_poly: &BigUintPolynomial<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &Table,
        rns_base: &RNSBase<T, M>,
        context: &mut DcrtGlevContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
    {
        let poly_length = table.poly_length();
        let big_uint_value_len = rns_base.big_uint_value_len();
        let big_uint_poly_len = big_uint_poly.len();
        let basis_value = basis.basis_value();

        debug_assert_eq!(big_uint_poly_len, big_uint_value_len * poly_length);

        let moduli = rns_base.moduli();
        let dcrt_glwe_len = self.0.len();

        context.clear();
        let DcrtGlevContextRefMut {
            adjust_big_uint_values,
            decomposed_unsigned_values,
            carries,
            multi_residues,
            compose_buffer: _,
        } = context.as_mut();

        debug_assert_eq!(adjust_big_uint_values.len(), big_uint_poly_len);
        debug_assert_eq!(decomposed_unsigned_values.len(), poly_length);
        debug_assert_eq!(carries.len(), poly_length);
        debug_assert_eq!(multi_residues.len(), poly_length * moduli.len());
        debug_assert_eq!(
            dcrt_glev.as_ref().len(),
            dcrt_glwe_len * basis.decompose_length()
        );

        basis.init_value_carry_slice_to(
            big_uint_poly.as_slice(),
            adjust_big_uint_values,
            carries,
            big_uint_value_len,
        );

        dcrt_glev
            .iter_dcrt_glwe(dcrt_glwe_len)
            .zip(basis.decomposer_iter())
            .for_each(|(dcrt_glwe, once_decomposer)| {
                once_decomposer.unsigned_decompose_slice_to(
                    adjust_big_uint_values.as_ref(),
                    decomposed_unsigned_values,
                    carries,
                    big_uint_value_len,
                );

                rns_base.wrapping_decompose_small_values_to(
                    decomposed_unsigned_values.as_ref(),
                    multi_residues,
                    poly_length,
                    basis_value,
                );

                table.transform_slice(multi_residues);

                self.add_dcrt_glwe_mul_dcrt_polynomial_assign(
                    &dcrt_glwe,
                    &DcrtPolynomial(&*multi_residues),
                    poly_length,
                    moduli,
                );
            });
    }
}

impl<S, T> DcrtGlwe<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Extracts slice of `a` and `b` of this [`DcrtGlwe<S, T>`].
    #[inline]
    pub fn a_b_slices(&self, mid: usize) -> (&[T], &[T]) {
        self.0.split_at(mid)
    }

    /// Extracts `a` and `b` of this [`DcrtGlwe<S, T>`].
    #[inline]
    pub fn a_b(&self, mid: usize) -> (DcrtPolynomialIter<'_, T>, DcrtPolynomial<&[T]>) {
        let (a, b) = self.0.split_at(mid);
        (DcrtPolynomialIter::new(a, b.len()), DcrtPolynomial(b))
    }

    /// Multiplies this DCRT GLWE by a Shoup factor and writes the result into `result`.
    pub fn mul_factor_to<F, A>(
        &self,
        scalar: &[F],
        result: &mut DcrtGlwe<A>,
        poly_length: usize,
        dcrt_poly_len: usize,
        moduli: &[T],
    ) where
        F: Copy + FactorSliceOps<T>,
        A: RawData<Elem = T> + DataMut,
    {
        self.iter_dcrt_poly(dcrt_poly_len)
            .zip(result.iter_dcrt_poly_mut(dcrt_poly_len))
            .for_each(|(in_dcrt_poly, mut out_dcrt_poly)| {
                in_dcrt_poly.mul_factor_to(scalar, &mut out_dcrt_poly, poly_length, moduli);
            });
    }

    /// Performs a multiplication on the `self` [`DcrtGlwe<S>`] with another `dcrt_polynomial` [`DcrtPolynomial<A>`],
    /// store the result into `result` [`DcrtGlwe<B>`].
    #[inline]
    pub fn mul_dcrt_polynomial_to<M, A, B>(
        &self,
        dcrt_poly: &DcrtPolynomial<A>,
        result: &mut DcrtGlwe<B>,
        poly_length: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let dcrt_poly_len = dcrt_poly.dcrt_poly_length();

        self.iter_dcrt_poly(dcrt_poly_len)
            .zip(result.iter_dcrt_poly_mut(dcrt_poly_len))
            .for_each(|(a, mut b)| {
                a.mul_to(dcrt_poly, &mut b, poly_length, moduli);
            });
    }
}
