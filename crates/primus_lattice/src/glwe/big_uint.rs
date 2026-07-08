use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_poly::{BigUintPolynomialIter, BigUintPolynomialIterMut};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use super::CrtGlwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`primus_poly::BigUintPolynomial`] with same poly length, `k` is the dimension.
#[derive(Clone)]
pub struct BigUintGlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(BigUintGlwe<S>);
impl_bytes_conversion!(BigUintGlwe<S>);
impl_zero!(BigUintGlwe<S>);
impl_iters!(BigUintGlwe);
impl_iter_sub_structure!(BigUintGlwe<S>, BigUintPolynomial, big_uint_poly);

impl<S, T> BigUintGlwe<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Composes the CRT representation in `crt_glwe` into this BigUint GLWE.
    #[inline]
    pub fn compose_assign<A, M>(
        &mut self,
        crt_glwe: &CrtGlwe<A>,
        poly_length: usize,
        crt_poly_len: usize,
        rns_base: &RNSBase<T, M>,
        compose_buffer: &mut [T],
    ) where
        A: RawData<Elem = T> + Data,
        M: FieldContext<T>,
    {
        let big_uint_value_len = rns_base.big_uint_value_len();
        let big_uint_poly_len = poly_length * big_uint_value_len;

        self.iter_big_uint_poly_mut(big_uint_poly_len)
            .zip(crt_glwe.iter_crt_poly(crt_poly_len))
            .for_each(|(mut big_uint_poly, crt_poly)| {
                rns_base.compose_polynomial_to(
                    &crt_poly,
                    &mut big_uint_poly,
                    poly_length,
                    compose_buffer,
                );
            });
    }
}

impl<S, T> BigUintGlwe<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Decomposes `self`.
    #[inline]
    pub fn decompose_to<A, M>(
        &self,
        result: &mut CrtGlwe<A>,
        poly_length: usize,
        crt_poly_len: usize,
        rns_base: &RNSBase<T, M>,
    ) where
        A: RawData<Elem = T> + DataMut,
        M: FieldContext<T>,
    {
        let big_uint_value_len = rns_base.big_uint_value_len();
        let big_uint_poly_len = poly_length * big_uint_value_len;

        self.iter_big_uint_poly(big_uint_poly_len)
            .zip(result.iter_crt_poly_mut(crt_poly_len))
            .for_each(|(big_uint_poly, mut crt_poly)| {
                rns_base.decompose_polynomial_to(&big_uint_poly, &mut crt_poly, poly_length);
            });
    }
}
