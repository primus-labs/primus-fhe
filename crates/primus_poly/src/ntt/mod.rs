use num_traits::Zero;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::{ByteCount, FheUint, Size};
use primus_reduce::ReduceMulAddSlice;

mod basic;

mod add;
mod inv;
mod mul;
mod neg;
mod sub;

/// Owned [`NttPolynomial`] backed by a [`Vec`].
pub type NttPolynomialOwned<T> = NttPolynomial<Vec<T>>;
/// Borrowed [`NttPolynomial`] backed by an immutable slice.
pub type NttPolynomialRef<'a, T> = NttPolynomial<&'a [T]>;
/// Mutably borrowed [`NttPolynomial`] backed by a mutable slice.
pub type NttPolynomialMut<'a, T> = NttPolynomial<&'a mut [T]>;

/// Raw NTT evaluations under one modulus, in the originating table's order.
///
/// This wrapper stores no ring length, modulus or transform identity. Empty,
/// arbitrary-length and packed storage are allowed; [`Self::len`] counts all
/// stored evaluations. Callers establish the complete layout before arithmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NttPolynomial<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_iters!(NttPolynomial, ntt_poly);

impl_views!(NttPolynomial);

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`NttPolynomial<S>`] from NTT evaluation storage.
    #[must_use]
    #[inline]
    pub fn new(values: S) -> Self {
        Self(values)
    }
}

impl<S, T> NttPolynomial<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Creates a [`NttPolynomial<S>`] with `len` zero NTT evaluations.
    #[must_use]
    #[inline]
    pub fn zero(len: usize) -> Self {
        Self(S::from_vec(vec![T::ZERO; len]))
    }

    /// Constructs a new ntt polynomial from a slice.
    #[must_use]
    #[inline]
    pub fn from_slice(polynomial: &[T]) -> Self {
        Self::new(S::from_slice(polynomial))
    }
}

impl<S, T> NttPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Extracts a mutable slice of the entire vector.
    ///
    /// Equivalent to `&mut s[..]`.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }

    /// Returns an iterator over mutable NTT values.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.0.iter_mut()
    }

    /// Copies NTT values from another slice.
    #[inline]
    pub fn copy_from(&mut self, src: impl AsRef<[T]>) {
        self.0.copy_from_slice(src.as_ref())
    }

    /// Sets `self` to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.0.fill(T::ZERO);
    }

    /// Performs `self = self + (a * b)`.
    #[inline]
    pub fn add_mul_assign<M, A, B>(
        &mut self,
        a: &NttPolynomial<A>,
        b: &NttPolynomial<B>,
        modulus: M,
    ) where
        M: Copy + ReduceMulAddSlice<T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        modulus.reduce_add_mul_slice_assign(self.as_mut_slice(), a.as_slice(), b.as_slice());
    }
}

impl<S, T> NttPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Extracts a slice containing the entire vector.
    ///
    /// Equivalent to `&s[..]`.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    /// Returns the total number of stored NTT evaluations, without validating a ring length.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the backing storage contains no NTT evaluations.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over NTT values.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.0.iter()
    }

    /// Returns `true` if `self` is equal to `0`.
    #[must_use]
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(Zero::is_zero)
    }

    /// Performs `result = self * b + c`.
    #[inline]
    pub fn mul_add_to<M, B, C, D>(
        &self,
        b: &NttPolynomial<B>,
        c: &NttPolynomial<C>,
        output: &mut NttPolynomial<D>,
        modulus: M,
    ) where
        M: Copy + ReduceMulAddSlice<T>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        modulus.reduce_mul_add_slice_to(
            self.as_slice(),
            b.as_slice(),
            c.as_slice(),
            output.as_mut_slice(),
        );
    }
}

impl<S, T> Size for NttPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn byte_count(&self) -> usize {
        self.0.len() * <T as ByteCount>::BYTES
    }
}
