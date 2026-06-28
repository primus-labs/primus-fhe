use num_traits::{ConstZero, Zero};
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::{ByteCount, FheUint, Size};
use primus_reduce::ReduceMulAdd;

mod basic;
mod random;

mod add;
mod mul;
mod neg;
mod sub;

/// Owned [`Polynomial`] backed by a [`Vec`].
pub type PolynomialOwned<T> = Polynomial<Vec<T>>;
/// Borrowed [`Polynomial`] backed by an immutable slice.
pub type PolynomialRef<'a, T> = Polynomial<&'a [T]>;
/// Mutably borrowed [`Polynomial`] backed by a mutable slice.
pub type PolynomialMut<'a, T> = Polynomial<&'a mut [T]>;

/// Represents a polynomial where coefficients are elements of a specified unsigned integer `T`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_iters!(Polynomial, poly);

impl<S, T> Polynomial<S>
where
    S: RawData<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`Polynomial<T>`].
    #[inline]
    pub fn new(poly: S) -> Self {
        Self(poly)
    }
}

impl<S, T> Polynomial<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Creates a [`Polynomial<T>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero(poly_length: usize) -> Self {
        Self(S::from_vec(vec![T::ZERO; poly_length]))
    }

    /// Drop self, and return the vector.
    #[inline]
    pub fn into_owned(self) -> S {
        self.0
    }

    /// Constructs a new polynomial from a slice.
    #[inline]
    pub fn from_slice(polynomial: &[T]) -> Self {
        Self::new(S::from_slice(polynomial))
    }
}

impl<S, T> Polynomial<S>
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
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
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
}

impl<S, T> Polynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Get the coefficient counts of polynomial.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.0.len()
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
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
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

    /// Evaluate the polynomial with the value `x`.
    #[inline]
    pub fn evaluate<M>(&self, x: T, modulus: M) -> T
    where
        M: Copy + ReduceMulAdd<T, Output = T>,
    {
        self.0.iter().rev().fold(<T as ConstZero>::ZERO, |acc, &a| {
            modulus.reduce_mul_add(acc, x, a)
        })
    }
}

impl<S, T> Size for Polynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    #[inline]
    fn byte_count(&self) -> usize {
        self.0.len() * <T as ByteCount>::BYTES
    }
}
