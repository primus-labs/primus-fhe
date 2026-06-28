use num_traits::Zero;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::{ByteCount, FheUint, Size};

mod add;
mod mul;
mod neg;
mod random;
mod sub;

/// This structure is used to store polynomials with large integer coefficients.
///
/// By the Chinese remainder theorem,
/// a large integer can be decomposed into several remainders.
///
/// If all the coefficients of a polynomial are decomposed in the same way,
/// several polynomials with relatively small coefficients can be obtained,
/// and the latter has better performance in addition and subtraction computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrtPolynomial<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_iters!(CrtPolynomial, crt_poly);

impl<S, T> CrtPolynomial<S>
where
    S: RawData<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`CrtPolynomial<T>`].
    #[inline]
    pub fn new(polys: S) -> Self {
        Self(polys)
    }
}

impl<S, T> CrtPolynomial<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Creates a [`CrtPolynomial<T>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero(crt_poly_len: usize) -> Self {
        Self(S::from_vec(vec![T::ZERO; crt_poly_len]))
    }

    /// Drop self, and return the underlying storage.
    #[inline]
    pub fn into_owned(self) -> S {
        self.0
    }
}

impl<S, T> CrtPolynomial<S>
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
    pub fn iter_each_modulus_mut(
        &mut self,
        poly_length: usize,
    ) -> std::slice::ChunksExactMut<'_, T> {
        self.0.chunks_exact_mut(poly_length)
    }

    /// Sets `self` to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.0.fill(T::ZERO);
    }

    /// Copy the coefficients from another slice.
    #[inline]
    pub fn copy_from<A>(&mut self, src: &CrtPolynomial<A>)
    where
        A: RawData<Elem = T> + Data,
    {
        self.0.copy_from_slice(src.0.as_slice());
    }
}

impl<S, T> CrtPolynomial<S>
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

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn iter_each_modulus(&self, poly_length: usize) -> std::slice::ChunksExact<'_, T> {
        self.0.chunks_exact(poly_length)
    }

    /// Returns `true` if `self` is equal to `0`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(Zero::is_zero)
    }

    /// Returns the number of elements in the backing storage.
    #[inline]
    pub fn crt_poly_length(&self) -> usize {
        self.0.len()
    }
}

impl<S, T> Size for CrtPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    #[inline]
    fn byte_count(&self) -> usize {
        self.0.len() * <T as ByteCount>::BYTES
    }
}

impl<S, T> AsRef<[T]> for CrtPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.0.as_slice()
    }
}

impl<S, T> AsMut<[T]> for CrtPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }
}
