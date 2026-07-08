use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{ArrayBase, NttPolynomial, NttPolynomialIter, NttPolynomialIterMut};
use primus_reduce::FieldContext;

use super::Glwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`NttPolynomial`] with same poly length, `k` is the dimension.
#[derive(Clone)]
pub struct NttGlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(NttGlwe<S>);
impl_bytes_conversion!(NttGlwe<S>);
impl_zero!(NttGlwe<S>);
impl_iters!(NttGlwe);
impl_iter_sub_structure!(NttGlwe<S>, NttPolynomial, ntt_poly);
impl_basic_operation_single_modulus!(NttGlwe<S>);
impl_intt!(NttGlwe<S>, Glwe);

impl<S, T> NttGlwe<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs a modular multiplication on the `self` [`NttGlwe<S>`] with another `ntt_poly` [`NttPolynomial<A>`].
    #[inline]
    pub fn mul_ntt_polynomial_assign<M, A>(&mut self, ntt_poly: &NttPolynomial<A>, modulus: M)
    where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
    {
        let poly_len = ntt_poly.poly_length();

        self.iter_ntt_poly_mut(poly_len).for_each(|mut poly| {
            poly.mul_assign(ntt_poly, modulus);
        });
    }
}

impl<S, T> NttGlwe<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Extracts slice of `a` and `b` of this [`NttGlwe<S>`].
    #[inline]
    pub fn a_b_slices(&self, mid: usize) -> (&[T], &[T]) {
        self.0.split_at(mid)
    }

    /// Extracts `a` and `b` of this [`NttGlwe<S>`].
    #[inline]
    pub fn a_b(&self, mid: usize) -> (NttPolynomialIter<'_, T>, NttPolynomial<&[T]>) {
        let (a, b) = self.0.split_at(mid);
        (NttPolynomialIter::new(a, b.len()), NttPolynomial(b))
    }

    /// Performs a modular multiplication on the `self` [`NttGlwe<S>`] with another `ntt_poly` [`NttPolynomial`],
    /// stores the result into `result`.
    #[inline]
    pub fn mul_ntt_polynomial_to<M, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        result: &mut NttGlwe<B>,
        modulus: M,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = ntt_poly.poly_length();

        self.iter_ntt_poly(poly_length)
            .zip(result.iter_ntt_poly_mut(poly_length))
            .for_each(|(x, mut y)| {
                x.mul_to(ntt_poly, &mut y, modulus);
            });
    }
}
