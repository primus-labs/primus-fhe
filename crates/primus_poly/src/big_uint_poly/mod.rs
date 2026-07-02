use num_traits::Zero;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::{BigUintIter, BigUintIterMut, FheUint};

mod add;
mod neg;
mod sub;

/// Represents a polynomial where coefficients are big unsigned integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigUintPolynomial<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_iters!(BigUintPolynomial, big_uint_poly);

impl<S, T> BigUintPolynomial<S>
where
    S: RawData<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`BigUintPolynomial<T>`].
    #[inline]
    pub fn new(big_uint_poly: S) -> Self {
        Self(big_uint_poly)
    }
}

impl<S, T> BigUintPolynomial<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Creates a [`BigUintPolynomial<S>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero(big_uint_poly_len: usize) -> Self {
        Self(S::from_vec(vec![T::ZERO; big_uint_poly_len]))
    }

    /// Drop self, and return the vector.
    #[inline]
    pub fn into_owned(self) -> S {
        self.0
    }

    /// Constructs a new polynomial from a slice.
    #[inline]
    pub fn from_slice(polynomial: &[T]) -> Self {
        Self(S::from_slice(polynomial))
    }
}

impl<S, T> BigUintPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
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

    /// Extracts a mutable slice of the entire vector.
    ///
    /// Equivalent to `&mut s[..]`.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }

    /// Returns an iterator that allows modifying each value or coefficient of the polynomial.
    #[inline]
    pub fn iter_mut(&mut self, value_len: usize) -> BigUintIterMut<'_, T> {
        BigUintIterMut::new(self.as_mut_slice(), value_len)
    }
}

impl<S, T> BigUintPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Returns `true` if `self` is equal to `0`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(Zero::is_zero)
    }

    /// Extracts a slice containing the entire vector.
    ///
    /// Equivalent to `&s[..]`.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn iter(&self, value_len: usize) -> BigUintIter<'_, T> {
        BigUintIter::new(self.as_slice(), value_len)
    }

    /// Returns the number of elements in the backing storage.
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}
