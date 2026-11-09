use num_complex::Complex64;
use primus_data::{Data, DataMut, DataOwned, RawData};

mod add;
mod mul;
mod neg;
mod sub;

/// Owned Fourier polynomial.
pub type FourierPolynomialOwned = FourierPolynomial<Vec<Complex64>>;
/// Borrowed Fourier polynomial.
pub type FourierPolynomialRef<'a> = FourierPolynomial<&'a [Complex64]>;
/// Mutably borrowed Fourier polynomial.
pub type FourierPolynomialMut<'a> = FourierPolynomial<&'a mut [Complex64]>;

/// A polynomial represented by its independent complex evaluations.
///
/// This raw wrapper stores no ring length or transform identity. Empty,
/// arbitrary-length and packed storage are allowed. [`Self::len`] counts all
/// complex values; only a complete single-polynomial layout has `N/2` values.
///
/// Arithmetic requires operands and outputs with equal numbers of values from
/// compatible Fourier transforms. It preserves their normalization and performs
/// no transform. Shape checks are debug diagnostics; callers must establish the
/// complete layout before arithmetic, since zipped loops consume only the common
/// prefix of mismatched slices.
#[derive(Debug, Clone, PartialEq)]
pub struct FourierPolynomial<S>(pub S)
where
    S: RawData<Elem = Complex64>;

/// Immutable iterator over Fourier polynomials.
#[derive(Debug, Clone)]
pub struct FourierPolynomialIter<'a> {
    iter: core::slice::ChunksExact<'a, Complex64>,
}
impl<'a> FourierPolynomialIter<'a> {
    /// Creates an iterator with `fourier_len` values per polynomial.
    ///
    /// Any trailing values that do not fill a complete polynomial are not yielded.
    ///
    /// # Panics
    ///
    /// Panics if `fourier_len` is zero.
    #[must_use]
    pub fn new(data: &'a [Complex64], fourier_len: usize) -> Self {
        Self {
            iter: data.chunks_exact(fourier_len),
        }
    }
}
impl<'a> Iterator for FourierPolynomialIter<'a> {
    type Item = FourierPolynomial<&'a [Complex64]>;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(FourierPolynomial)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
    fn count(self) -> usize {
        self.iter.len()
    }
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth(n).map(FourierPolynomial)
    }
    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }
}
impl core::iter::DoubleEndedIterator for FourierPolynomialIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(FourierPolynomial)
    }
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth_back(n).map(FourierPolynomial)
    }
}
impl core::iter::ExactSizeIterator for FourierPolynomialIter<'_> {}
impl core::iter::FusedIterator for FourierPolynomialIter<'_> {}

/// Mutable iterator over Fourier polynomials.
#[derive(Debug)]
pub struct FourierPolynomialIterMut<'a> {
    iter: core::slice::ChunksExactMut<'a, Complex64>,
}
impl<'a> FourierPolynomialIterMut<'a> {
    /// Creates an iterator with `fourier_len` values per polynomial.
    ///
    /// Any trailing values that do not fill a complete polynomial are not yielded.
    ///
    /// # Panics
    ///
    /// Panics if `fourier_len` is zero.
    #[must_use]
    pub fn new(data: &'a mut [Complex64], fourier_len: usize) -> Self {
        Self {
            iter: data.chunks_exact_mut(fourier_len),
        }
    }
}
impl<'a> Iterator for FourierPolynomialIterMut<'a> {
    type Item = FourierPolynomial<&'a mut [Complex64]>;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(FourierPolynomial)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
    fn count(self) -> usize {
        self.iter.len()
    }
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth(n).map(FourierPolynomial)
    }
    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }
}
impl core::iter::DoubleEndedIterator for FourierPolynomialIterMut<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(FourierPolynomial)
    }
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth_back(n).map(FourierPolynomial)
    }
}
impl core::iter::ExactSizeIterator for FourierPolynomialIterMut<'_> {}
impl core::iter::FusedIterator for FourierPolynomialIterMut<'_> {}

impl<S: RawData<Elem = Complex64>> FourierPolynomial<S> {
    /// Creates a new [`FourierPolynomial<S>`] from Fourier evaluation storage.
    #[must_use]
    pub fn new(values: S) -> Self {
        Self(values)
    }

    /// Consumes the wrapper and returns its storage without copying.
    /// Borrowed storage remains borrowed; this does not create an owned buffer.
    #[must_use]
    #[inline]
    pub fn into_inner(self) -> S {
        self.0
    }
}
impl<S: DataOwned<Elem = Complex64>> FourierPolynomial<S> {
    /// Creates a [`FourierPolynomial<S>`] with `len` zero complex values.
    #[must_use]
    pub fn zero(len: usize) -> Self {
        Self(S::from_vec(vec![Complex64::default(); len]))
    }
    /// Clones a Fourier polynomial from a slice.
    #[must_use]
    pub fn from_slice(data: &[Complex64]) -> Self {
        Self(S::from_slice(data))
    }
}
impl<S: Data<Elem = Complex64>> FourierPolynomial<S> {
    /// Returns all Fourier values.
    pub fn as_slice(&self) -> &[Complex64] {
        self.0.as_slice()
    }
    /// Returns the total number of stored complex values, without validating a ring length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Returns whether the backing storage contains no complex values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Returns an iterator over Fourier values.
    pub fn iter(&self) -> core::slice::Iter<'_, Complex64> {
        self.0.iter()
    }
    /// Returns whether every Fourier value is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|x| *x == Complex64::default())
    }
}
impl<S: DataMut<Elem = Complex64>> FourierPolynomial<S> {
    /// Returns all Fourier values mutably.
    pub fn as_mut_slice(&mut self) -> &mut [Complex64] {
        self.0.as_mut_slice()
    }
    /// Returns a mutable iterator over Fourier values.
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, Complex64> {
        self.0.iter_mut()
    }
    /// Copies Fourier values from `src`.
    pub fn copy_from(&mut self, src: impl AsRef<[Complex64]>) {
        self.0.copy_from_slice(src.as_ref());
    }
    /// Sets every Fourier value to zero.
    pub fn set_zero(&mut self) {
        self.0.fill(Complex64::default());
    }
}
impl<S: Data<Elem = Complex64>> AsRef<[Complex64]> for FourierPolynomial<S> {
    fn as_ref(&self) -> &[Complex64] {
        self.as_slice()
    }
}
impl<S: DataMut<Elem = Complex64>> AsMut<[Complex64]> for FourierPolynomial<S> {
    fn as_mut(&mut self) -> &mut [Complex64] {
        self.as_mut_slice()
    }
}

impl<S> FourierPolynomial<S>
where
    S: Data<Elem = Complex64>,
{
    /// Borrows the complete storage as a shared view of the same representation.
    /// No elements are copied or transformed, and no layout is validated.
    #[must_use]
    #[inline]
    pub fn as_view(&self) -> FourierPolynomial<&[Complex64]> {
        FourierPolynomial(self.0.as_slice())
    }
}

impl<'a, S> From<&'a FourierPolynomial<S>> for FourierPolynomial<&'a [Complex64]>
where
    S: Data<Elem = Complex64>,
{
    #[inline]
    fn from(value: &'a FourierPolynomial<S>) -> Self {
        value.as_view()
    }
}

impl<S> FourierPolynomial<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Borrows the complete storage as an exclusive view of the same representation.
    /// No elements are copied or transformed, and no layout is validated.
    #[must_use]
    #[inline]
    pub fn as_mut_view(&mut self) -> FourierPolynomial<&mut [Complex64]> {
        FourierPolynomial(self.0.as_mut_slice())
    }
}

impl<'a, S> From<&'a mut FourierPolynomial<S>> for FourierPolynomial<&'a mut [Complex64]>
where
    S: DataMut<Elem = Complex64>,
{
    #[inline]
    fn from(value: &'a mut FourierPolynomial<S>) -> Self {
        value.as_mut_view()
    }
}
