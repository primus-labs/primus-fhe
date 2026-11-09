use primus_integer::{FheUint, UnsignedInteger};

mod ops;
mod slice;

#[cfg(feature = "simd")]
mod simd;

/// An explicit, representable power-of-two modulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PowOf2Modulus<T: UnsignedInteger> {
    /// The reduction mask, equal to the modulus minus one.
    mask: T,
}

impl<T: UnsignedInteger> PowOf2Modulus<T> {
    /// Creates a [`PowOf2Modulus<T>`] for the given modulus.
    ///
    /// # Panics
    ///
    /// Panics unless `value` is a representable power of two greater than one.
    #[must_use]
    #[inline]
    pub fn new(value: T) -> Self {
        assert!(
            value > T::ONE && value.is_power_of_two(),
            "PowOf2Modulus::new: modulus must be a representable power of two greater than one"
        );
        Self {
            mask: value - T::ONE,
        }
    }

    /// Creates a [`PowOf2Modulus<T>`] from a precomputed reduction mask.
    ///
    /// # Panics
    ///
    /// Panics unless `mask = 2^k - 1` for some `1 ≤ k < T::BITS`.
    #[must_use]
    #[inline]
    pub fn with_mask(mask: T) -> Self {
        let leading_zeros = mask.leading_zeros();
        assert!(
            !mask.is_zero() && leading_zeros > 0 && mask.count_zeros() == leading_zeros,
            "PowOf2Modulus::with_mask: mask must be 2^k - 1 for 1 <= k < T::BITS; use NativeModulus for the full-width modulus"
        );
        Self { mask }
    }

    /// Returns the modulus.
    #[must_use]
    #[inline]
    pub fn value(self) -> T {
        self.mask + T::ONE
    }

    /// Returns the reduction mask, which is the modulus minus one.
    #[must_use]
    #[inline]
    pub const fn mask(self) -> T {
        self.mask
    }
}

impl<T: FheUint> primus_reduce::Modulus for PowOf2Modulus<T> {
    type ValueT = T;

    #[inline]
    fn explicit_value(self) -> Option<Self::ValueT> {
        Some(self.mask + T::ONE)
    }

    #[inline(always)]
    fn minus_one(self) -> Self::ValueT {
        self.mask
    }
}

impl<T: FheUint> primus_reduce::ExplicitModulus for PowOf2Modulus<T> {
    #[inline(always)]
    fn value(self) -> Self::ValueT {
        self.mask + T::ONE
    }
}
