use primus_integer::{FheUint, UnsignedInteger};

mod ops;
mod slice;

#[cfg(feature = "simd")]
mod simd;

/// Power of 2 modulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PowOf2Modulus<T: UnsignedInteger> {
    /// The special value for performing `reduce`.
    ///
    /// It's equal to modulus value sub one.
    mask: T,
}

impl<T: UnsignedInteger> PowOf2Modulus<T> {
    /// Creates a [`PowOf2Modulus<T>`].
    ///
    /// - `value`: The value of the modulus.
    #[inline]
    pub fn new(value: T) -> Self {
        assert!(
            value > T::ONE && value.is_power_of_two(),
            "The value is not a power of 2."
        );
        Self {
            mask: value - T::ONE,
        }
    }

    /// Creates a [`PowOf2Modulus<T>`].
    ///
    /// - `mask`: modulus value minus one.
    #[inline]
    pub fn with_mask(mask: T) -> Self {
        let leading_zeros = mask.leading_zeros();
        assert!(mask.count_zeros() == leading_zeros && !mask.is_zero());
        assert!(
            leading_zeros > 0,
            "NativeModulus<T> supports modulus value such as 2⁸, 2¹⁶, 2³², 2⁶⁴, 2¹²⁸"
        );
        Self { mask }
    }

    /// Returns the value of this [`PowOf2Modulus<T>`].
    #[inline]
    pub fn value(self) -> T {
        self.mask + T::ONE
    }

    /// Returns the mask of this [`PowOf2Modulus<T>`],
    /// which is equal to modulus value sub one.
    #[inline]
    pub const fn mask(self) -> T {
        self.mask
    }
}

impl<T: FheUint> primus_reduce::Modulus for PowOf2Modulus<T> {
    type ValueT = T;

    #[inline]
    fn value(self) -> Option<Self::ValueT> {
        Some(self.mask + T::ONE)
    }

    #[inline(always)]
    unsafe fn value_unchecked(self) -> Self::ValueT {
        self.mask + T::ONE
    }

    #[inline(always)]
    fn minus_one(self) -> Self::ValueT {
        self.mask
    }
}
