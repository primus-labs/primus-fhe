use std::mem::MaybeUninit;

use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_distr::DiscreteGaussian;
use primus_factor::FactorSliceOps;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{ArrayBase, NttPolynomial, Polynomial, PolynomialIter, PolynomialIterMut};
use primus_reduce::{FieldContext, ReduceNeg, ReduceNegAssign, ReduceNegSlice};

use crate::lwe::{Lwe, MultiMsgLwe};

use super::NttRlwe;

/// An owned RLWE sample backed by a [`Vec<T>`].
pub type RlweOwned<T> = Rlwe<Vec<T>>;

/// A cryptographic structure for Ring Learning with Errors (RLWE).
///
/// ## Structure of the `data`
///
/// |------a------|------b------|
///
/// where `a` and `b` are [`Polynomial`] with same poly length.
#[derive(Clone)]
pub struct Rlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Rlwe<S>);
impl_bytes_conversion!(Rlwe<S>);
impl_zero!(Rlwe<S>);
impl_iters!(Rlwe);
impl_iter_sub_structure!(Rlwe<S>, Polynomial, poly);
impl_basic_operation_single_modulus!(Rlwe<S>);
impl_ntt!(Rlwe<S>, NttRlwe);

impl<S, T> Rlwe<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Creates a new [`Rlwe<S>`] with reference of [`Polynomial<A>`].
    #[inline]
    pub fn from_ref<A>(a: &Polynomial<A>, b: &Polynomial<A>) -> Self
    where
        A: RawData<Elem = T> + Data,
    {
        debug_assert_eq!(a.poly_length(), b.poly_length());
        Self(S::from_vec([a.as_ref(), b.as_ref()].concat()))
    }
}

impl<T: FheUint> Rlwe<Vec<T>> {
    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe_locally<M>(self, modulus: M) -> Lwe<Vec<T>>
    where
        M: Copy + ReduceNegSlice<T>,
    {
        let mut data = self.0;

        let poly_len = data.len() / 2;
        data.truncate(poly_len + 1);

        let chunk = &mut data[1..poly_len];

        chunk.reverse();
        modulus.reduce_neg_slice_assign(chunk);

        Lwe::new(data)
    }

    /// Sample extract a [`MultiMsgLwe<T>`] with several encrypted messages.
    pub fn extract_first_few_lwe_locally<M>(self, count: usize, modulus: M) -> MultiMsgLwe<Vec<T>>
    where
        M: Copy + ReduceNegSlice<T>,
    {
        let mut data = self.0;
        let poly_len = data.len() / 2;

        data.truncate(poly_len + count);

        data[1..poly_len].reverse();
        modulus.reduce_neg_slice_assign(&mut data[1..poly_len]);

        MultiMsgLwe::new(data)
    }

    /// Generate a [`Rlwe<Vec<T>>`] sample which encrypts `0`.
    pub fn generate_random_zero_sample<R, Table, M, A>(
        secret_key: &NttPolynomial<A>,
        gaussian: &DiscreteGaussian<T>,
        ntt_table: &Table,
        modulus: M,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        M: FieldContext<T>,
    {
        let poly_length = secret_key.poly_length();

        let mut data = Rlwe::zero(poly_length * 2);

        let (a, b) = data.a_b_mut_slices();

        Polynomial(&mut *a).random_assign(modulus, rng);

        b.copy_from_slice(a);
        ntt_table.transform_slice(b);
        NttPolynomial(&mut *b).mul_assign(secret_key, modulus);
        ntt_table.inverse_transform_slice(b);

        Polynomial(b).add_random_gaussian_assign(gaussian, modulus, rng);

        data
    }
}

impl<S, T> Rlwe<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Extracts mutable slice of `a` and `b` of this [`Rlwe<S>`].
    #[inline]
    pub fn a_b_mut_slices(&mut self) -> (&mut [T], &mut [T]) {
        let mid = self.0.len() >> 1;
        unsafe { self.0.split_at_mut_unchecked(mid) }
    }

    /// Multiplies each coefficient of both `a` and `b` by `scalar` modulo `modulus` in place.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: FieldContext<T>,
    {
        ArrayBase(self.as_mut()).mul_scalar_assign(scalar, modulus);
    }

    /// Multiplies each coefficient of both `a` and `b` by a Shoup `factor` modulo `modulus` in place.
    #[inline]
    pub fn mul_factor_assign<F>(&mut self, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
    {
        ArrayBase(self.as_mut()).mul_factor_assign(factor, modulus);
    }
}

impl<S, T> Rlwe<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Extracts slice of `a` and `b` of this [`Rlwe<S>`].
    #[inline]
    pub fn a_b_slices(&self) -> (&[T], &[T]) {
        let mid = self.0.len() >> 1;
        unsafe { self.0.split_at_unchecked(mid) }
    }

    /// Performs a multiplication on the `self` [`Rlwe<S>`] with another `ntt_polynomial` [`NttPolynomial<A>`],
    /// store the result into `result` [`NttRlwe<B>`].
    #[inline]
    pub fn mul_ntt_polynomial_to<M, Table, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        result: &mut NttRlwe<B>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = ntt_table.poly_length();

        result.0.copy_from_slice(self.as_ref());

        result.0.chunks_exact_mut(poly_length).for_each(|poly| {
            ntt_table.transform_slice(poly);
            NttPolynomial(poly).mul_assign(ntt_poly, modulus);
        });
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe_with_index<M>(&self, index: usize, modulus: M) -> Lwe<Vec<T>>
    where
        M: Copy + ReduceNeg<T, Output = T>,
    {
        let poly_len = self.0.len() / 2;

        assert!(index < poly_len);

        let src = self.0.as_slice();
        let split = index + 1;

        let mut data: Vec<MaybeUninit<T>> = Vec::with_capacity(poly_len + 1);
        unsafe {
            data.set_len(poly_len + 1);
        }

        data[..split]
            .iter_mut()
            .zip(src[..split].iter().rev())
            .for_each(|(x, &y)| {
                x.write(y);
            });

        data[split..poly_len]
            .iter_mut()
            .zip(src[split..poly_len].iter().rev())
            .for_each(|(x, &y)| {
                x.write(modulus.reduce_neg(y));
            });

        data[poly_len].write(src[poly_len + index]);

        Lwe::new(unsafe { std::mem::transmute::<Vec<MaybeUninit<T>>, Vec<T>>(data) })
    }

    /// Extracts a [`MultiMsgLwe`] with several encrypted messages from RLWE.
    #[inline]
    pub fn extract_first_few_lwe<M>(&self, count: usize, modulus: M) -> MultiMsgLwe<Vec<T>>
    where
        M: Copy + ReduceNeg<T, Output = T> + ReduceNegAssign<T>,
    {
        let poly_len = self.0.len() / 2;
        let src = self.0.as_slice();

        let mut data: Vec<MaybeUninit<T>> = Vec::with_capacity(poly_len + count);
        unsafe {
            data.set_len(poly_len + count);
        }

        data[0].write(src[0]);

        data[1..poly_len]
            .iter_mut()
            .zip(src[1..poly_len].iter().rev())
            .for_each(|(x, &y)| {
                x.write(modulus.reduce_neg(y));
            });

        data[poly_len..]
            .iter_mut()
            .zip(src[poly_len..].iter())
            .for_each(|(x, &y)| {
                x.write(y);
            });

        MultiMsgLwe::new(unsafe { std::mem::transmute::<Vec<MaybeUninit<T>>, Vec<T>>(data) })
    }

    /// Extract an LWE sample from RLWE.
    #[inline]
    pub fn extract_lwe<M>(&self, modulus: M) -> Lwe<Vec<T>>
    where
        M: Copy + ReduceNeg<T, Output = T> + ReduceNegAssign<T>,
    {
        let poly_len = self.0.len() / 2;
        let src = self.0.as_slice();

        let mut data: Vec<MaybeUninit<T>> = Vec::with_capacity(poly_len + 1);
        unsafe {
            data.set_len(poly_len + 1);
        }

        data[0].write(src[0]);

        data[1..poly_len]
            .iter_mut()
            .zip(src[1..poly_len].iter().rev())
            .for_each(|(x, &y)| {
                x.write(modulus.reduce_neg(y));
            });

        data[poly_len].write(src[poly_len]);

        Lwe::new(unsafe { std::mem::transmute::<Vec<MaybeUninit<T>>, Vec<T>>(data) })
    }
}
