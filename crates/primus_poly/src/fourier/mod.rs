use num_complex::Complex64;
use primus_data::{Data, DataMut, DataOwned, RawData};

mod add;
mod mul;
mod neg;
mod sub;

/// Owned [`FourierPolynomial`] backed by a [`Vec`].
pub type FourierPolynomialOwned = FourierPolynomial<Vec<Complex64>>;
/// Borrowed [`FourierPolynomial`] backed by an immutable slice.
pub type FourierPolynomialRef<'a> = FourierPolynomial<&'a [Complex64]>;
/// Mutably borrowed [`FourierPolynomial`] backed by a mutable slice.
pub type FourierPolynomialMut<'a> = FourierPolynomial<&'a mut [Complex64]>;

/// A container for interleaved complex Fourier-domain values.
///
/// Represents one negacyclic FFT component in the Fourier domain under
/// `Z[X] / (X^N + 1)`. Unlike coefficient [`Polynomial`](crate::Polynomial),
/// this type does not carry a modulus or support modular arithmetic —
/// Fourier operations are approximate floating-point arithmetic.
///
/// # Element type
///
/// Uses [`Complex64`] (interleaved double-precision complex numbers).
/// Pointwise arithmetic kernels live in
/// [`primus_fft::complex64::arithmetic`].
///
/// # Storage polymorphism
///
/// `S` abstracts over the memory backend. Common aliases:
/// - [`FourierPolynomialOwned`] — owned `Vec<Complex64>`
/// - [`FourierPolynomialRef`] — borrowed `&[Complex64]`
/// - [`FourierPolynomialMut`] — mutably borrowed `&mut [Complex64]`
#[derive(Debug, Clone, PartialEq)]
pub struct FourierPolynomial<S>(pub S)
where
    S: RawData<Elem = Complex64>;

// ---------------------------------------------------------------------------
// Iterators (manual — impl_iters! requires T: FheUint)
// ---------------------------------------------------------------------------

/// Immutable chunked iterator over [`FourierPolynomial`] components.
#[derive(Debug, Clone)]
pub struct FourierPolynomialIter<'a> {
    /// The underlying chunked iterator.
    pub iter: core::slice::ChunksExact<'a, Complex64>,
}

impl<'a> FourierPolynomialIter<'a> {
    /// Creates a new iterator that yields `FourierPolynomialRef` chunks
    /// of `fourier_len` elements each.
    #[inline]
    pub fn new(data: &'a [Complex64], fourier_len: usize) -> Self {
        Self {
            iter: data.chunks_exact(fourier_len),
        }
    }
}

impl<'a> Iterator for FourierPolynomialIter<'a> {
    type Item = FourierPolynomial<&'a [Complex64]>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(FourierPolynomial)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth(n).map(FourierPolynomial)
    }

    #[inline]
    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }
}

impl<'a> core::iter::FusedIterator for FourierPolynomialIter<'a> {}
impl<'a> core::iter::DoubleEndedIterator for FourierPolynomialIter<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(FourierPolynomial)
    }

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth_back(n).map(FourierPolynomial)
    }
}
impl<'a> core::iter::ExactSizeIterator for FourierPolynomialIter<'a> {}

/// Mutable chunked iterator over [`FourierPolynomial`] components.
#[derive(Debug)]
pub struct FourierPolynomialIterMut<'a> {
    /// The underlying mutable chunked iterator.
    pub iter: core::slice::ChunksExactMut<'a, Complex64>,
}

impl<'a> FourierPolynomialIterMut<'a> {
    /// Creates a new mutable iterator that yields `FourierPolynomialMut` chunks
    /// of `fourier_len` elements each.
    #[inline]
    pub fn new(data: &'a mut [Complex64], fourier_len: usize) -> Self {
        Self {
            iter: data.chunks_exact_mut(fourier_len),
        }
    }
}

impl<'a> Iterator for FourierPolynomialIterMut<'a> {
    type Item = FourierPolynomial<&'a mut [Complex64]>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(FourierPolynomial)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth(n).map(FourierPolynomial)
    }

    #[inline]
    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }
}

impl<'a> core::iter::FusedIterator for FourierPolynomialIterMut<'a> {}
impl<'a> core::iter::DoubleEndedIterator for FourierPolynomialIterMut<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(FourierPolynomial)
    }

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth_back(n).map(FourierPolynomial)
    }
}
impl<'a> core::iter::ExactSizeIterator for FourierPolynomialIterMut<'a> {}

// ---------------------------------------------------------------------------
// Methods: RawData<Elem = Complex64>
// ---------------------------------------------------------------------------

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = Complex64>,
{
    /// Creates a new [`FourierPolynomial`].
    #[inline]
    pub fn new(values: S) -> Self {
        Self(values)
    }
}

// ---------------------------------------------------------------------------
// Methods: DataOwned
// ---------------------------------------------------------------------------

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + DataOwned,
{
    /// Creates a [`FourierPolynomial`] with all elements set to zero.
    #[inline]
    pub fn zero(fourier_length: usize) -> Self {
        Self(S::from_vec(vec![Complex64::new(0.0, 0.0); fourier_length]))
    }

    /// Consumes `self`, returning the underlying storage.
    #[inline]
    pub fn into_owned(self) -> S {
        self.0
    }

    /// Constructs a new Fourier polynomial by cloning elements from a slice.
    #[inline]
    pub fn from_slice(data: &[Complex64]) -> Self {
        Self::new(S::from_slice(data))
    }
}

// ---------------------------------------------------------------------------
// Methods: DataMut
// ---------------------------------------------------------------------------

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + DataMut,
{
    /// Extracts a mutable slice of all elements.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [Complex64] {
        self.0.as_mut_slice()
    }

    /// Returns a mutable iterator over the elements.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, Complex64> {
        self.0.iter_mut()
    }

    /// Copies elements from `src` into `self`. Lengths must match.
    #[inline]
    pub fn copy_from(&mut self, src: impl AsRef<[Complex64]>) {
        self.0.copy_from_slice(src.as_ref());
    }

    /// Sets all elements to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.0.fill(Complex64::new(0.0, 0.0));
    }
}

// ---------------------------------------------------------------------------
// Methods: Data (read-only)
// ---------------------------------------------------------------------------

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + Data,
{
    /// Extracts a slice containing all elements.
    #[inline]
    pub fn as_slice(&self) -> &[Complex64] {
        self.0.as_slice()
    }

    /// Returns the Fourier length (number of complex frequency values).
    #[inline]
    pub fn fourier_length(&self) -> usize {
        self.0.len()
    }

    /// Returns a read-only iterator over the elements.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, Complex64> {
        self.0.iter()
    }

    /// Returns `true` if all elements are zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        let zero = Complex64::new(0.0, 0.0);
        self.0.iter().all(|&x| x == zero)
    }
}

// ---------------------------------------------------------------------------
// Convenience trait impls
// ---------------------------------------------------------------------------

impl<S> AsRef<[Complex64]> for FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + Data,
{
    #[inline]
    fn as_ref(&self) -> &[Complex64] {
        self.as_slice()
    }
}

impl<S> AsMut<[Complex64]> for FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + DataMut,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [Complex64] {
        self.as_mut_slice()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_as_slice() {
        let data = vec![
            Complex64::new(1.0, 0.0),
            Complex64::new(0.0, 1.0),
            Complex64::new(2.0, 3.0),
        ];
        let poly = FourierPolynomial::new(data.clone());
        assert_eq!(poly.as_slice(), data.as_slice());
        assert_eq!(poly.fourier_length(), 3);
    }

    #[test]
    fn test_zero() {
        let poly = FourierPolynomialOwned::zero(4);
        assert_eq!(poly.fourier_length(), 4);
        assert!(poly.is_zero());
    }

    #[test]
    fn test_set_zero() {
        let data = vec![Complex64::new(1.0, 2.0); 4];
        let mut poly = FourierPolynomial::new(data);
        assert!(!poly.is_zero());
        poly.set_zero();
        assert!(poly.is_zero());
    }

    #[test]
    fn test_copy_from() {
        let src = vec![Complex64::new(1.0, 0.0), Complex64::new(0.0, 1.0)];
        let mut poly = FourierPolynomialOwned::zero(2);
        poly.copy_from(&src);
        assert_eq!(poly.as_slice(), src.as_slice());
    }

    #[test]
    fn test_from_slice() {
        let data = vec![
            Complex64::new(1.0, 0.0),
            Complex64::new(2.0, 0.0),
            Complex64::new(3.0, 0.0),
        ];
        let poly = FourierPolynomialOwned::from_slice(&data);
        assert_eq!(poly.as_slice(), data.as_slice());
    }

    #[test]
    fn test_into_owned() {
        let data = vec![Complex64::new(1.0, 0.0), Complex64::new(0.0, 1.0)];
        let poly = FourierPolynomialOwned::from_slice(&data);
        let vec: Vec<Complex64> = poly.into_owned();
        assert_eq!(vec, data);
    }

    #[test]
    fn test_iter() {
        let data = vec![Complex64::new(1.0, 0.0), Complex64::new(2.0, 0.0)];
        let poly = FourierPolynomial::new(data.clone());
        let collected: Vec<Complex64> = poly.iter().copied().collect();
        assert_eq!(collected, data);
    }

    #[test]
    fn test_iter_mut() {
        let data = vec![Complex64::new(1.0, 0.0), Complex64::new(2.0, 0.0)];
        let mut poly = FourierPolynomial::new(data.clone());
        for x in poly.iter_mut() {
            *x = Complex64::new(x.re + 1.0, 0.0);
        }
        assert_eq!(poly.as_slice()[0], Complex64::new(2.0, 0.0));
        assert_eq!(poly.as_slice()[1], Complex64::new(3.0, 0.0));
    }

    #[test]
    fn test_fourier_iterator_chunks() {
        // Flat storage: 2 Fourier polynomials, each of length 3
        let data = vec![
            // poly 0
            Complex64::new(1.0, 0.0),
            Complex64::new(2.0, 0.0),
            Complex64::new(3.0, 0.0),
            // poly 1
            Complex64::new(4.0, 0.0),
            Complex64::new(5.0, 0.0),
            Complex64::new(6.0, 0.0),
        ];
        let iter = FourierPolynomialIter::new(&data, 3);
        let polys: Vec<_> = iter.collect();
        assert_eq!(polys.len(), 2);
        assert_eq!(
            polys[0].as_slice(),
            &[
                Complex64::new(1.0, 0.0),
                Complex64::new(2.0, 0.0),
                Complex64::new(3.0, 0.0),
            ]
        );
        assert_eq!(
            polys[1].as_slice(),
            &[
                Complex64::new(4.0, 0.0),
                Complex64::new(5.0, 0.0),
                Complex64::new(6.0, 0.0),
            ]
        );
    }

    #[test]
    fn test_fourier_iterator_mut_chunks() {
        let mut data = vec![Complex64::new(0.0, 0.0); 6];
        let iter = FourierPolynomialIterMut::new(&mut data, 3);
        for mut poly in iter {
            poly.set_zero();
        }
        assert!(data.iter().all(|&x| x == Complex64::new(0.0, 0.0)));
    }

    #[test]
    fn test_fourier_iterator_empty() {
        let data: Vec<Complex64> = vec![];
        let iter = FourierPolynomialIter::new(&data, 3);
        assert_eq!(iter.count(), 0);
    }

    #[test]
    fn test_fourier_iterator_trailing_remainder() {
        // 5 elements with chunk size 3: only 1 full chunk, 2 remainder elements dropped
        let data = vec![Complex64::new(0.0, 0.0); 5];
        let iter = FourierPolynomialIter::new(&data, 3);
        assert_eq!(iter.count(), 1); // trailing 2 elements omitted by chunks_exact
    }

    #[test]
    fn test_fourier_polynomial_borrowed() {
        let data = vec![Complex64::new(1.0, 0.0), Complex64::new(2.0, 0.0)];
        // FourierPolynomialRef via new() on a slice reference
        let poly_ref = FourierPolynomial::new(data.as_slice());
        assert_eq!(poly_ref.fourier_length(), 2);
        assert_eq!(poly_ref.as_slice(), data.as_slice());
    }

    #[test]
    fn test_is_zero() {
        let poly = FourierPolynomialOwned::zero(4);
        assert!(poly.is_zero());

        let poly2 =
            FourierPolynomial::new(vec![Complex64::new(1.0, 0.0), Complex64::new(0.0, 0.0)]);
        assert!(!poly2.is_zero());
    }

    #[test]
    fn test_as_ref_and_as_mut() {
        let mut poly = FourierPolynomialOwned::zero(2);
        // AsMut
        poly.as_mut()[0] = Complex64::new(1.0, 1.0);
        // AsRef
        assert_eq!(poly.as_ref()[0], Complex64::new(1.0, 1.0));
        assert_eq!(poly.as_ref()[1], Complex64::new(0.0, 0.0));
    }
}
