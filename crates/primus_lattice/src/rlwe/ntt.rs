use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{ArrayBase, NttPolynomial, NttPolynomialIter, NttPolynomialIterMut};
use primus_reduce::FieldContext;

use super::Rlwe;

pub type NttRlweOwned<T> = NttRlwe<Vec<T>>;

/// A cryptographic structure for Ring Learning with Errors (RLWE).
///
/// ## Structure of the `data`
///
/// |------a------|------b------|
///
/// where `a` and `b` are [`NttPolynomial`] with same poly length.
#[derive(Clone)]
pub struct NttRlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(NttRlwe<S>);
impl_bytes_conversion!(NttRlwe<S>);
impl_zero!(NttRlwe<S>);
impl_iters!(NttRlwe);
impl_iter_sub_structure!(NttRlwe<S>, NttPolynomial, ntt_poly);
impl_basic_operation_single_modulus!(NttRlwe<S>);
impl_intt!(NttRlwe<S>, Rlwe);

impl<S, T> NttRlwe<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Creates a new [`NttRlwe<S>`] with reference of [`NttPolynomial<A>`].
    #[inline]
    pub fn from_ref<A>(a: &NttPolynomial<A>, b: &NttPolynomial<A>) -> Self
    where
        A: RawData<Elem = T> + Data,
    {
        debug_assert_eq!(a.poly_length(), b.poly_length());
        Self(S::from_vec([a.as_ref(), b.as_ref()].concat()))
    }
}

impl<S, T> NttRlwe<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Extracts mutable slice of `a` and `b` of this [`NttRlwe<S>`].
    #[inline]
    pub fn a_b_mut_slices(&mut self) -> (&mut [T], &mut [T]) {
        let mid = self.0.len() >> 1;
        unsafe { self.0.split_at_mut_unchecked(mid) }
    }

    /// Extracts mutable slice of `a` and `b` of this [`NttRlwe<S>`].
    #[inline]
    pub fn a_b_mut(&mut self) -> (NttPolynomial<&mut [T]>, NttPolynomial<&mut [T]>) {
        let mid = self.0.len() >> 1;
        let (a, b) = unsafe { self.0.split_at_mut_unchecked(mid) };
        (NttPolynomial(a), NttPolynomial(b))
    }

    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: FieldContext<T>,
    {
        ArrayBase(self.as_mut()).mul_scalar_assign(scalar, modulus);
    }

    /// Performs a modular multiplication on the `self` [`NttRlwe<S>`] with another `ntt_poly` [`NttPolynomial<A>`].
    #[inline]
    pub fn mul_ntt_polynomial_assign<M, A>(&mut self, ntt_poly: &NttPolynomial<A>, modulus: M)
    where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
    {
        let poly_len = ntt_poly.poly_length();

        self.iter_ntt_poly_mut(poly_len).for_each(|mut p| {
            p.mul_assign(ntt_poly, modulus);
        });
    }

    pub fn add_ntt_rlwe_mul_ntt_polynomial_assign<M, A, B>(
        &mut self,
        ntt_rlwe: &NttRlwe<A>,
        ntt_poly: &NttPolynomial<B>,
        modulus: M,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
    {
        let poly_len = ntt_poly.poly_length();
        self.iter_ntt_poly_mut(poly_len)
            .zip(ntt_rlwe.iter_ntt_poly(poly_len))
            .for_each(|(mut x, y)| {
                x.add_mul_assign(&y, ntt_poly, modulus);
            });
    }
}

impl<S, T> NttRlwe<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Extracts slice of `a` and `b` of this [`NttRlwe<S>`].
    #[inline]
    pub fn a_b_slices(&self) -> (&[T], &[T]) {
        let mid = self.0.len() >> 1;
        unsafe { self.0.split_at_unchecked(mid) }
    }

    /// Extracts `a` and `b` of this [`NttRlwe<S>`].
    #[inline]
    pub fn a_b(&self) -> (NttPolynomial<&[T]>, NttPolynomial<&[T]>) {
        let mid = self.0.len() >> 1;
        let (a, b) = unsafe { self.0.split_at_unchecked(mid) };
        (NttPolynomial(a), NttPolynomial(b))
    }

    /// Performs a modular multiplication on the `self` [`NttRlwe<S>`] with another `polynomial` [`NttPolynomial`],
    /// stores the result into `result`.
    #[inline]
    pub fn mul_ntt_polynomial_to<M, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        result: &mut NttRlwe<B>,
        modulus: M,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_len = ntt_poly.poly_length();

        self.iter_ntt_poly(poly_len)
            .zip(result.iter_ntt_poly_mut(poly_len))
            .for_each(|(x, mut y)| {
                x.mul_to(ntt_poly, &mut y, modulus);
            });
    }
}
