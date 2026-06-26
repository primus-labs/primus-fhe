use num_traits::Zero;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::{ByteCount, FheUint, Size};
use primus_reduce::{LazyReduceMulAddSlice, ReduceMulAddSlice};

mod basic;
mod random;

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

/// Represents a ntt polynomial where values are elements of a specified numeric `T`.
/// It stores the values of the polynomial at some particular points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NttPolynomial<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_iters!(NttPolynomial, ntt_poly);

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`NttPolynomial<T>`].
    #[inline]
    pub fn new(values: S) -> Self {
        Self(values)
    }
}

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Creates a [`NttPolynomial<T>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero(poly_length: usize) -> Self {
        Self(S::from_vec(vec![T::ZERO; poly_length]))
    }

    /// Drop self, and return the data.
    #[inline]
    pub fn into_owned(self) -> S {
        self.0
    }

    /// Constructs a new ntt polynomial from a slice.
    #[inline]
    pub fn from_slice(polynomial: &[T]) -> Self {
        Self::new(S::from_slice(polynomial))
    }
}

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Extracts a mutable slice of the entire vector.
    ///
    /// Equivalent to `&mut s[..]`.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }

    /// Returns an iterator that allows modifying each value or coefficient of the polynomial.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.0.iter_mut()
    }

    /// Copy the coefficients from another slice.
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
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
    {
        modulus.reduce_add_mul_slice_assign(self.as_mut_slice(), a.as_slice(), b.as_slice());
    }

    /// Performs `self = self + (a * b)`.
    #[inline]
    pub fn add_mul_assign_fast<M, A, B>(
        &mut self,
        a: &NttPolynomial<A>,
        b: &NttPolynomial<B>,
        modulus: M,
    ) where
        M: Copy + LazyReduceMulAddSlice<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
    {
        modulus.lazy_reduce_add_mul_slice_assign(self.as_mut_slice(), a.as_slice(), b.as_slice());
    }
}

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Extracts a slice containing the entire vector.
    ///
    /// Equivalent to `&s[..]`.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    /// Get the `coefficient counts`/`polynomial length` of polynomial.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.0.iter()
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn copied_iter(&self) -> core::iter::Copied<core::slice::Iter<'_, T>> {
        self.0.iter().copied()
    }

    /// Returns `true` if `self` is equal to `0`.
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
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + Data,
        D: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_mul_add_slice_to(
            self.as_slice(),
            b.as_slice(),
            c.as_slice(),
            output.as_mut_slice(),
        );
    }

    /// Performs `result = self * b + c`.
    #[inline]
    pub fn mul_add_to_fast<M, B, C, D>(
        &self,
        b: &NttPolynomial<B>,
        c: &NttPolynomial<C>,
        output: &mut NttPolynomial<D>,
        modulus: M,
    ) where
        M: Copy + LazyReduceMulAddSlice<T>,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + Data,
        D: RawData<Elem = T> + DataMut,
    {
        modulus.lazy_reduce_mul_add_slice_to(
            self.as_slice(),
            b.as_slice(),
            c.as_slice(),
            output.as_mut_slice(),
        );
    }
}

impl<S, T> Size for NttPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    #[inline]
    fn byte_count(&self) -> usize {
        self.0.len() * <T as ByteCount>::BYTES
    }
}
