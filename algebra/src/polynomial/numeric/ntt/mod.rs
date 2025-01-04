use num_traits::ConstZero;

mod basic;
mod random;

mod add;
mod mul;
mod neg;
mod sub;

/// Represents a polynomial where coefficients are elements of a specified numeric `T`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NumNttPolynomial<T> {
    data: Vec<T>,
}

impl<T> NumNttPolynomial<T> {
    /// Creates a new [`NumNttPolynomial<T>`].
    #[inline]
    pub fn new(values: Vec<T>) -> Self {
        Self { data: values }
    }

    /// Drop self, and return the data.
    #[inline]
    pub fn inner_data(self) -> Vec<T> {
        self.data
    }

    /// Extracts a slice containing the entire vector.
    ///
    /// Equivalent to `&s[..]`.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.data.as_slice()
    }

    /// Extracts a mutable slice of the entire vector.
    ///
    /// Equivalent to `&mut s[..]`.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.data.as_mut_slice()
    }

    /// Get the coefficient counts of polynomial.
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.data.len()
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<T> {
        self.data.iter()
    }

    /// Returns an iterator that allows modifying each value or coefficient of the polynomial.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<T> {
        self.data.iter_mut()
    }

    /// Resize the coefficient count of the polynomial.
    #[inline]
    pub fn resize_with<FN>(&mut self, new_degree: usize, f: FN)
    where
        FN: FnMut() -> T,
    {
        self.data.resize_with(new_degree, f);
    }
}

impl<T: Clone> NumNttPolynomial<T> {
    /// Constructs a new ntt polynomial from a slice.
    #[inline]
    pub fn from_slice(polynomial: &[T]) -> Self {
        Self::new(polynomial.to_vec())
    }

    /// Resize the coefficient count of the ntt polynomial.
    #[inline]
    pub fn resize(&mut self, new_degree: usize, value: T) {
        self.data.resize(new_degree, value);
    }
}

impl<T: Copy> NumNttPolynomial<T> {
    /// Copy the coefficients from another slice.
    #[inline]
    pub fn copy_from(&mut self, src: impl AsRef<[T]>) {
        self.data.copy_from_slice(src.as_ref())
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn copied_iter(&self) -> core::iter::Copied<core::slice::Iter<'_, T>> {
        self.data.iter().copied()
    }
}

impl<T> NumNttPolynomial<T>
where
    T: Copy + ConstZero,
{
    /// Creates a [`NumNttPolynomial<T>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            data: vec![T::ZERO; coeff_count],
        }
    }

    /// Returns `true` if `self` is equal to `0`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.data.is_empty() || self.data.iter().all(T::is_zero)
    }

    /// Sets `self` to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.data.fill(T::ZERO);
    }
}
