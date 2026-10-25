use num_traits::Zero;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::{BigUintIter, BigUintIterMut, FheUint};

mod add;
mod neg;
mod sub;

/// Raw coefficient-major storage for fixed-width big unsigned coefficients.
///
/// Each coefficient is a contiguous little-endian limb block. This wrapper
/// stores no limb width or coefficient count; [`Self::len`] counts limbs.
///
/// # Correctness
///
/// Modular arithmetic uses the modulus's nonzero limb count as the coefficient
/// width. All input and output buffers must have equal lengths, divisible by
/// that width, and each input coefficient must be less than the modulus, as
/// required by the corresponding [`primus_integer::BigUint`] operation.
/// Incomplete trailing coefficients are not processed by the iterators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigUintPolynomial<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_iters!(BigUintPolynomial, big_uint_poly);

impl_views!(BigUintPolynomial);

impl<S, T> BigUintPolynomial<S>
where
    S: RawData<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`BigUintPolynomial<S>`] from coefficient-major limb storage.
    #[must_use]
    #[inline]
    pub fn new(big_uint_poly: S) -> Self {
        Self(big_uint_poly)
    }
}

impl<S, T> BigUintPolynomial<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Creates a [`BigUintPolynomial<S>`] with `big_uint_poly_len` zero limbs.
    #[must_use]
    #[inline]
    pub fn zero(big_uint_poly_len: usize) -> Self {
        Self(S::from_vec(vec![T::ZERO; big_uint_poly_len]))
    }

    /// Constructs a new polynomial from a slice.
    #[must_use]
    #[inline]
    pub fn from_slice(polynomial: &[T]) -> Self {
        Self(S::from_slice(polynomial))
    }
}

impl<S, T> BigUintPolynomial<S>
where
    S: DataMut<Elem = T>,
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

    /// Returns complete mutable coefficients of `value_len` limbs each.
    ///
    /// Each coefficient is little-endian; an incomplete trailing block is omitted.
    ///
    /// # Panics
    ///
    /// Panics if `value_len` is zero.
    #[inline]
    pub fn iter_mut(&mut self, value_len: usize) -> BigUintIterMut<'_, T> {
        BigUintIterMut::new(self.as_mut_slice(), value_len)
    }
}

impl<S, T> BigUintPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Returns `true` if `self` is equal to `0`.
    #[must_use]
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

    /// Returns complete coefficients of `value_len` limbs each.
    ///
    /// Each coefficient is little-endian; an incomplete trailing block is omitted.
    ///
    /// # Panics
    ///
    /// Panics if `value_len` is zero.
    #[inline]
    pub fn iter(&self, value_len: usize) -> BigUintIter<'_, T> {
        BigUintIter::new(self.as_slice(), value_len)
    }

    /// Returns the number of limbs in the backing storage, not the coefficient count.
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}
